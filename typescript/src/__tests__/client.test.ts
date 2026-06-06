import { AgentTrustClient } from '../client';
import { AuthenticationError, AgentTrustError, NetworkError } from '../errors';

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch;

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

describe('AgentTrustClient', () => {
  it('initializes with default base URL', () => {
    const client = new AgentTrustClient();
    expect(client.agents).toBeDefined();
    expect(client.tokens).toBeDefined();
    expect(client.actions).toBeDefined();
    expect(client.telemetry).toBeDefined();
  });

  it('initializes with custom options', () => {
    const client = new AgentTrustClient({
      baseUrl: 'http://custom:9090',
      apiKey: 'sk_test_123',
      timeout: 5000,
    });
    expect(client).toBeDefined();
  });

  it('creates from environment variables', () => {
    process.env.AGENTTRUST_URL = 'http://env-url:8080';
    process.env.AGENTTRUST_API_KEY = 'sk_env_key';
    const client = AgentTrustClient.fromEnv();
    expect(client).toBeDefined();
    delete process.env.AGENTTRUST_URL;
    delete process.env.AGENTTRUST_API_KEY;
  });

  it('checks service health', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({ status: 'healthy', service: 'gateway' }));
    const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080' });
    const health = await client.health();
    expect(health).toEqual({ status: 'healthy', service: 'gateway' });
    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/health',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('sets API key on all HTTP clients', () => {
    const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080' });
    // Should not throw
    client.setApiKey('sk_test_new_key');
  });
});

describe('AgentsAPI', () => {
  const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080', apiKey: 'sk_test' });

  it('creates an agent', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      agent: {
        id: 'agent-123',
        name: 'test-agent',
        org_id: 'org-1',
        framework: 'custom',
        status: 'active',
        capabilities: ['web_search'],
        created_at: '2026-01-01T00:00:00Z',
      },
    }));

    const agent = await client.agents.create({
      name: 'test-agent',
      framework: 'custom',
      capabilities: ['web_search'],
    });

    expect(agent.id).toBe('agent-123');
    expect(agent.name).toBe('test-agent');
    expect(agent.capabilities).toEqual(['web_search']);
    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/api/v1/agents',
      expect.objectContaining({ method: 'POST' }),
    );
  });

  it('lists agents', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      agents: [
        { id: 'a1', name: 'agent-1', status: 'active', framework: 'custom', capabilities: [] },
        { id: 'a2', name: 'agent-2', status: 'revoked', framework: 'langchain', capabilities: ['search'] },
      ],
    }));

    const agents = await client.agents.list();
    expect(agents).toHaveLength(2);
    expect(agents[0].name).toBe('agent-1');
    expect(agents[1].status).toBe('revoked');
  });

  it('gets agent by ID', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      id: 'agent-123',
      name: 'my-agent',
      status: 'active',
      framework: 'custom',
      capabilities: ['read'],
    }));

    const agent = await client.agents.get('agent-123');
    expect(agent.id).toBe('agent-123');
    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/api/v1/agents/agent-123',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('revokes an agent', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({ success: true }));

    const result = await client.agents.revoke('agent-123', 'compromised');
    expect(result).toBe(true);
    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/api/v1/agents/agent-123/revoke',
      expect.objectContaining({ method: 'POST' }),
    );
  });
});

describe('ActionsAPI', () => {
  const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080', apiKey: 'sk_test' });

  it('checks an action (allowed)', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      allowed: true,
      check_id: 'chk-1',
      confidence: 0.95,
      guard_tier: 'fast',
      latency_ms: 12,
      reason: 'capability match',
    }));

    const result = await client.actions.check({
      agentId: 'agent-1',
      toolName: 'web_search',
      toolInputSummary: 'search query',
    });

    expect(result.allowed).toBe(true);
    expect(result.confidence).toBe(0.95);
    expect(result.guardTier).toBe('fast');
  });

  it('checks an action (denied)', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      allowed: false,
      confidence: 0.95,
      guard_tier: 'fast',
      reason: 'capability not registered',
    }));

    const result = await client.actions.check({
      agentId: 'agent-1',
      toolName: 'delete_all',
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('capability not registered');
  });
});

describe('TelemetryAPI', () => {
  const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080', apiKey: 'sk_test' });

  it('reports telemetry events', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({ accepted: true, events_processed: 2 }));

    const result = await client.telemetry.report('agent-1', 'sess-1', [
      { event_type: 'tool_end', tool_name: 'search', duration_ms: 100, success: true, timestamp: '2026-01-01T00:00:00Z' },
      { event_type: 'tool_error', tool_name: 'analyze', duration_ms: 50, success: false, timestamp: '2026-01-01T00:00:01Z', error_type: 'timeout' },
    ]);

    expect(result.accepted).toBe(true);
    expect(result.events_processed).toBe(2);
  });
});

describe('Error handling', () => {
  const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080' });

  it('throws AuthenticationError on 401', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({ message: 'invalid key' }, 401));
    await expect(client.health()).rejects.toThrow(AuthenticationError);
  });

  it('throws AgentTrustError on 500', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({ message: 'server error' }, 500));
    await expect(client.health()).rejects.toThrow(AgentTrustError);
  });

  it('throws NetworkError on fetch failure', async () => {
    mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));
    await expect(client.health()).rejects.toThrow(NetworkError);
  });
});
