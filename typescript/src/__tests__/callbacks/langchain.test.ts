import { AgentTrustClient } from '../../client';
import { AgentTrustError } from '../../errors';
import { AgentTrustLangChainHandler } from '../../callbacks/langchain';

const mockFetch = jest.fn();
global.fetch = mockFetch;

Object.defineProperty(global, 'crypto', {
  value: { randomUUID: () => 'test-session-id' },
  configurable: true,
});

beforeEach(() => {
  mockFetch.mockReset();
});

function jsonResponse(data: unknown, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(JSON.stringify(data)),
  });
}

const RUN_ID_1 = '11111111-1111-1111-1111-111111111111';
const RUN_ID_2 = '22222222-2222-2222-2222-222222222222';

describe('AgentTrustLangChainHandler', () => {
  const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080', apiKey: 'sk_test' });

  it('extends LangChain BaseCallbackHandler (instanceof check)', () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { BaseCallbackHandler } = require('@langchain/core/callbacks/base');
    const handler = new AgentTrustLangChainHandler(client, 'agent-1');
    expect(handler).toBeInstanceOf(BaseCallbackHandler);
    expect((handler as unknown as { name: string }).name).toBe('AgentTrustLangChainHandler');
  });

  it('allows tool execution when Guardian permits', async () => {
    mockFetch.mockReturnValueOnce(
      jsonResponse({ allowed: true, check_id: 'chk-1', confidence: 0.95, guard_tier: 'fast' })
    );

    const handler = new AgentTrustLangChainHandler(client, 'agent-1');
    await expect(
      handler.handleToolStart(
        { name: 'web_search', id: ['langchain', 'tools', 'web_search'] },
        'query about AI',
        RUN_ID_1
      )
    ).resolves.toBeUndefined();

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const callBody = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(callBody.action_name).toBe('web_search');
  });

  it('throws AgentTrustError when Guardian denies (blockOnDeny=true default)', async () => {
    mockFetch.mockReturnValueOnce(
      jsonResponse({ allowed: false, reason: 'capability not registered' })
    );

    const handler = new AgentTrustLangChainHandler(client, 'agent-1');
    await expect(
      handler.handleToolStart({ name: 'drop_database' }, '{}', RUN_ID_1)
    ).rejects.toThrow(AgentTrustError);
  });

  it('reports tool error telemetry on handleToolError', async () => {
    // start (allowed)
    mockFetch.mockReturnValueOnce(jsonResponse({ allowed: true }));
    // telemetry flush
    mockFetch.mockReturnValue(jsonResponse({ accepted: true, events_processed: 1 }));

    const handler = new AgentTrustLangChainHandler(client, 'agent-1');
    await handler.handleToolStart({ name: 'fetch_url' }, 'http://x', RUN_ID_2);
    await handler.handleToolError(new TypeError('boom'), RUN_ID_2);
    await handler.flush();

    // Find the telemetry call (last one)
    const telemetryCall = mockFetch.mock.calls.find((c) =>
      String(c[0]).includes('/telemetry/report')
    );
    expect(telemetryCall).toBeDefined();
    const body = JSON.parse(telemetryCall![1].body);
    expect(body.events).toHaveLength(1);
    expect(body.events[0].event_type).toBe('tool_error');
    expect(body.events[0].success).toBe(false);
    expect(body.events[0].error_type).toBe('TypeError');
  });

  it('flushes telemetry on top-level handleChainEnd', async () => {
    // start allowed
    mockFetch.mockReturnValueOnce(jsonResponse({ allowed: true }));
    // tool_end => no fetch (buffered) until flush
    // telemetry flush
    mockFetch.mockReturnValue(jsonResponse({ accepted: true, events_processed: 1 }));

    const handler = new AgentTrustLangChainHandler(client, 'agent-1');
    await handler.handleToolStart({ name: 'search' }, 'q', RUN_ID_1);
    await handler.handleToolEnd('result', RUN_ID_1);

    // No parentRunId => top-level chain end => triggers flush
    await handler.handleChainEnd({}, RUN_ID_1);

    const telemetryCall = mockFetch.mock.calls.find((c) =>
      String(c[0]).includes('/telemetry/report')
    );
    expect(telemetryCall).toBeDefined();
    const body = JSON.parse(telemetryCall![1].body);
    expect(body.events).toHaveLength(1);
    expect(body.events[0].event_type).toBe('tool_end');
    expect(body.events[0].success).toBe(true);
  });

  it('does NOT flush on nested chain end (has parentRunId)', async () => {
    const handler = new AgentTrustLangChainHandler(client, 'agent-1');
    await handler.handleChainEnd({}, RUN_ID_1, 'parent-run-id');
    // No telemetry calls because we never reported anything AND nested chain
    // ends don't flush.
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('fail-open: allows tool when Guardian unreachable + failOpen=true', async () => {
    mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

    const handler = new AgentTrustLangChainHandler(client, 'agent-1', { failOpen: true });
    await expect(
      handler.handleToolStart({ name: 'web_search' }, 'q', RUN_ID_1)
    ).resolves.toBeUndefined();
  });
});
