import { AgentTrustClient, AgentTrustGuard } from '../client';
import { AgentTrustError } from '../errors';

const mockFetch = jest.fn();
global.fetch = mockFetch;

// Mock crypto.randomUUID
Object.defineProperty(global, 'crypto', {
  value: { randomUUID: () => 'test-session-id' },
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

describe('AgentTrustGuard', () => {
  const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080', apiKey: 'sk_test' });

  describe('check()', () => {
    it('returns true when action is allowed', async () => {
      mockFetch.mockReturnValueOnce(jsonResponse({
        allowed: true, check_id: 'chk-1', confidence: 0.95, guard_tier: 'fast',
      }));

      const guard = new AgentTrustGuard(client, 'agent-1');
      const result = await guard.check('web_search', 'query about AI');
      expect(result).toBe(true);
    });

    it('throws when denied and blockOnDeny=true (default)', async () => {
      mockFetch.mockReturnValueOnce(jsonResponse({
        allowed: false, reason: 'capability not registered', confidence: 0.95,
      }));

      const guard = new AgentTrustGuard(client, 'agent-1');
      await expect(guard.check('drop_database')).rejects.toThrow(AgentTrustError);
    });

    it('returns false when denied and blockOnDeny=false', async () => {
      mockFetch.mockReturnValueOnce(jsonResponse({
        allowed: false, reason: 'not registered',
      }));

      const guard = new AgentTrustGuard(client, 'agent-1', { blockOnDeny: false });
      const result = await guard.check('dangerous_tool');
      expect(result).toBe(false);
    });

    it('throws when service unreachable and failOpen=false (default)', async () => {
      mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

      const guard = new AgentTrustGuard(client, 'agent-1');
      await expect(guard.check('web_search')).rejects.toThrow('Guardian unreachable');
    });

    it('returns true when service unreachable and failOpen=true', async () => {
      mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

      const guard = new AgentTrustGuard(client, 'agent-1', { failOpen: true });
      const result = await guard.check('web_search');
      expect(result).toBe(true);
    });

    it('uses custom session ID', async () => {
      mockFetch.mockReturnValueOnce(jsonResponse({ allowed: true }));

      const guard = new AgentTrustGuard(client, 'agent-1', { sessionId: 'my-session' });
      await guard.check('tool_a');

      const callBody = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(callBody.session_id).toBe('my-session');
    });

    it('truncates tool input summary to 200 chars', async () => {
      mockFetch.mockReturnValueOnce(jsonResponse({ allowed: true }));

      const guard = new AgentTrustGuard(client, 'agent-1');
      const longInput = 'x'.repeat(500);
      await guard.check('tool_a', longInput);

      const callBody = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(callBody.action_input_summary.length).toBeLessThanOrEqual(200);
    });
  });

  describe('report()', () => {
    it('buffers telemetry events', () => {
      const guard = new AgentTrustGuard(client, 'agent-1');
      guard.report('search', true, 120);
      guard.report('analyze', false, 50, 'timeout');
      // No fetch calls yet — events are buffered
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('auto-flushes at 10 events', async () => {
      mockFetch.mockReturnValue(jsonResponse({ accepted: true, events_processed: 10 }));

      const guard = new AgentTrustGuard(client, 'agent-1');
      for (let i = 0; i < 10; i++) {
        guard.report(`tool_${i}`, true, 10);
      }

      // Wait for async flush
      await new Promise(r => setTimeout(r, 50));
      expect(mockFetch).toHaveBeenCalled();

      const callBody = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(callBody.events).toHaveLength(10);
      expect(callBody.agent_id).toBe('agent-1');
    });
  });

  describe('flush()', () => {
    it('sends buffered events to telemetry API', async () => {
      mockFetch.mockReturnValueOnce(jsonResponse({ accepted: true, events_processed: 2 }));

      const guard = new AgentTrustGuard(client, 'agent-1');
      guard.report('search', true, 120);
      guard.report('analyze', true, 200);

      await guard.flush();

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const callBody = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(callBody.events).toHaveLength(2);
      expect(callBody.events[0].tool_name).toBe('search');
      expect(callBody.events[1].tool_name).toBe('analyze');
    });

    it('does nothing when buffer is empty', async () => {
      const guard = new AgentTrustGuard(client, 'agent-1');
      await guard.flush();
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('clears buffer after flush even on failure', async () => {
      mockFetch.mockRejectedValueOnce(new Error('network down'));
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      const guard = new AgentTrustGuard(client, 'agent-1');
      guard.report('tool_a', true, 10);
      await guard.flush();

      // Buffer should be cleared
      mockFetch.mockReset();
      await guard.flush();
      expect(mockFetch).not.toHaveBeenCalled();

      consoleSpy.mockRestore();
    });
  });
});
