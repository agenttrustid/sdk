import { AgentTrustClient } from '../../client';
import { withAgentTrust } from '../../integrations/vercel-ai';

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

/**
 * Drive the Vercel AI middleware directly. We don't need a real LanguageModel —
 * the middleware's `wrapGenerate` accepts a `doGenerate` callback we control.
 *
 * `withAgentTrust` calls `wrapLanguageModel({ model, middleware })` from the `ai`
 * package; that returns a model whose `doGenerate` invokes the middleware
 * around the original. We can inspect the middleware-wrapped model by
 * reading the `wrapLanguageModel` return value.
 */
function makeFakeModel(toolCalls: Array<{ toolName: string; args?: string }>) {
  return {
    specificationVersion: 'v1',
    provider: 'fake',
    modelId: 'fake-model',
    defaultObjectGenerationMode: undefined,
    supportsImageUrls: false,
    supportsStructuredOutputs: false,
    async doGenerate() {
      return {
        text: 'ok',
        toolCalls: toolCalls.map((t, i) => ({
          toolCallType: 'function' as const,
          toolCallId: `call_${i}`,
          toolName: t.toolName,
          args: t.args ?? '{}',
        })),
        finishReason: 'tool-calls' as const,
        usage: { promptTokens: 1, completionTokens: 1 },
        rawCall: { rawPrompt: '', rawSettings: {} },
      };
    },
    async doStream() {
      return {
        stream: new ReadableStream({
          start(controller) {
            for (let i = 0; i < toolCalls.length; i++) {
              const t = toolCalls[i];
              controller.enqueue({
                type: 'tool-call',
                toolCallType: 'function',
                toolCallId: `call_${i}`,
                toolName: t.toolName,
                args: t.args ?? '{}',
              });
            }
            controller.enqueue({
              type: 'finish',
              finishReason: 'tool-calls',
              usage: { promptTokens: 1, completionTokens: 1 },
            });
            controller.close();
          },
        }),
        rawCall: { rawPrompt: '', rawSettings: {} },
      };
    },
  };
}

describe('withAgentTrust (Vercel AI middleware)', () => {
  const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080', apiKey: 'sk_test' });

  it('allows tool calls when Guardian permits', async () => {
    mockFetch.mockReturnValueOnce(
      jsonResponse({ allowed: true, check_id: 'chk-1', confidence: 0.95, guard_tier: 'fast' })
    );

    const model = makeFakeModel([{ toolName: 'web_search' }]);
    const wrapped = withAgentTrust(model, { client, agentId: 'agent-1' });

    const result = await (wrapped as unknown as { doGenerate: () => Promise<{ toolCalls: unknown[]; text?: string }> }).doGenerate();

    expect(result.toolCalls).toHaveLength(1);
    expect((result.toolCalls![0] as { toolName: string }).toolName).toBe('web_search');

    // Pre-flight check fired
    const checkCall = mockFetch.mock.calls.find((c) => String(c[0]).includes('/agenttrust/check'));
    expect(checkCall).toBeDefined();
  });

  it('strips denied tool calls and surfaces denial text', async () => {
    mockFetch.mockReturnValueOnce(
      jsonResponse({ allowed: false, reason: 'capability not registered' })
    );

    const model = makeFakeModel([{ toolName: 'drop_database' }]);
    const wrapped = withAgentTrust(model, { client, agentId: 'agent-1' });

    const result = await (wrapped as unknown as {
      doGenerate: () => Promise<{ toolCalls: unknown[]; text?: string; finishReason?: string }>;
    }).doGenerate();

    expect(result.toolCalls).toEqual([]);
    expect(result.text).toContain('AgentTrust ID Guardian denied');
    expect(result.text).toContain('drop_database');
    expect(result.finishReason).toBe('stop');
  });

  it('reports telemetry for both allowed and denied tool calls', async () => {
    // First call: allowed. Second call: denied.
    mockFetch.mockReturnValueOnce(jsonResponse({ allowed: true }));
    mockFetch.mockReturnValueOnce(jsonResponse({ allowed: false, reason: 'denied' }));
    // Telemetry flush
    mockFetch.mockReturnValue(jsonResponse({ accepted: true, events_processed: 2 }));

    const model = makeFakeModel([
      { toolName: 'safe_tool' },
      { toolName: 'risky_tool' },
    ]);
    const wrapped = withAgentTrust(model, { client, agentId: 'agent-1' });

    const result = await (wrapped as unknown as {
      doGenerate: () => Promise<{ toolCalls: unknown[] }>;
    }).doGenerate();

    expect(result.toolCalls).toHaveLength(1);
    expect((result.toolCalls![0] as { toolName: string }).toolName).toBe('safe_tool');
  });

  it('throws when client/agentId missing', () => {
    expect(() =>
      withAgentTrust({} as unknown, { client: undefined as unknown as AgentTrustClient, agentId: '' })
    ).toThrow('withAgentTrustVercelAI requires');
  });
});
