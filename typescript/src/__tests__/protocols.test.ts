import { AgentTrustClient, primaryUrl, trustScore } from '../client';
import { AgentTrustError } from '../errors';

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

describe('AgentCardsAPI', () => {
  const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080', apiKey: 'sk_test' });

  // A2A v1.0 Agent Card sample.
  const mockCard = {
    name: 'research-agent',
    description: 'An agent that researches and summarizes the web.',
    version: '1.0.0',
    supportedInterfaces: [
      {
        url: 'https://agents.example.com/research',
        protocolBinding: 'JSONRPC',
        protocolVersion: '1.0',
        tenant: 'acme',
      },
      {
        url: 'https://agents.example.com/research/grpc',
        protocolBinding: 'GRPC',
        protocolVersion: '1.0',
      },
    ],
    provider: { organization: 'Acme Corp', url: 'https://acme.com' },
    capabilities: {
      streaming: true,
      push_notifications: false,
      extensions: [
        {
          uri: 'https://agenttrust.id/ext/trust/v1',
          description: 'AgentTrust trust score',
          required: false,
          params: { ati_trust_score: 85, ati_guardian_tier: 'fast' },
        },
      ],
    },
    securitySchemes: { bearer: { type: 'http', scheme: 'bearer' } },
    securityRequirements: [{ bearer: [] }],
    defaultInputModes: ['text/plain'],
    defaultOutputModes: ['text/plain'],
    skills: [
      {
        id: 'search',
        name: 'Web Search',
        description: 'Search the web',
        tags: ['search', 'web'],
        examples: ['Search for the latest AI news'],
      },
      {
        id: 'summarize',
        name: 'Summarize',
        description: 'Summarize content',
        tags: ['summary'],
      },
    ],
    documentationUrl: 'https://acme.com/docs',
    iconUrl: 'https://acme.com/icon.png',
  };

  it('generates an agent card', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse(mockCard));

    const card = await client.agentCards.generate('agent-123');

    expect(card.name).toBe('research-agent');
    expect(card.description).toBe('An agent that researches and summarizes the web.');
    expect(card.provider?.organization).toBe('Acme Corp');
    expect(card.version).toBe('1.0.0');
    expect(card.capabilities.streaming).toBe(true);
    expect(card.capabilities.pushNotifications).toBe(false);
    expect(card.supportedInterfaces).toHaveLength(2);
    expect(card.supportedInterfaces?.[0].protocolBinding).toBe('JSONRPC');
    expect(card.securitySchemes?.bearer.scheme).toBe('bearer');
    expect(card.defaultInputModes).toEqual(['text/plain']);
    expect(card.skills).toHaveLength(2);
    expect(card.skills[0].id).toBe('search');
    expect(card.skills[0].tags).toEqual(['search', 'web']);

    // v1.0 helpers
    expect(primaryUrl(card)).toBe('https://agents.example.com/research');
    expect(trustScore(card)).toBe(85);

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/api/v1/agents/agent-123/card',
      expect.objectContaining({ method: 'POST' }),
    );
  });

  it('parses a legacy cached card without v1.0 fields (no throw)', async () => {
    const legacyCard = {
      name: 'legacy-agent',
      version: '0.9.0',
      url: 'https://agents.example.com/legacy',
      capabilities: { streaming: false, push_notifications: true },
      skills: [{ id: 'echo', name: 'Echo', description: 'Echo', tags: [] }],
    };
    mockFetch.mockReturnValueOnce(jsonResponse(legacyCard));

    const card = await client.agentCards.get('agent-legacy');

    expect(card.name).toBe('legacy-agent');
    expect(card.supportedInterfaces).toBeUndefined();
    expect(card.signatures).toBeUndefined();
    // primaryUrl falls back to the legacy top-level url
    expect(primaryUrl(card)).toBe('https://agents.example.com/legacy');
    // trustScore defaults to 0 when the trust extension is absent
    expect(trustScore(card)).toBe(0);
  });

  it('gets an agent card', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse(mockCard));

    const card = await client.agentCards.get('agent-123');

    expect(card.name).toBe('research-agent');
    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/api/v1/agents/agent-123/card',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('publishes an agent card', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse(mockCard));

    const card = await client.agentCards.publish('agent-123');

    expect(card.name).toBe('research-agent');
    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/api/v1/agents/agent-123/card/publish',
      expect.objectContaining({ method: 'PUT' }),
    );
  });

  it('gets a public agent card', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse(mockCard));

    const card = await client.agentCards.getPublic('agent-123');

    expect(card.name).toBe('research-agent');
    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/a2a/agents/agent-123/agent.json',
      expect.objectContaining({ method: 'GET' }),
    );
  });
});

describe('A2AAPI', () => {
  const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080', apiKey: 'sk_test' });

  const mockTask = {
    id: 'task-001',
    source_agent_id: 'agent-a',
    target_agent_id: 'agent-b',
    status: 'completed',
    message: { role: 'user', content: 'Analyze this data' },
    artifacts: [{ type: 'text', data: 'Analysis result' }],
    metadata: { priority: 'high' },
    created_at: '2026-02-01T00:00:00Z',
    updated_at: '2026-02-01T00:01:00Z',
  };

  it('sends a task via JSON-RPC', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      jsonrpc: '2.0',
      result: mockTask,
      id: '1',
    }));

    const task = await client.a2a.sendTask({
      sourceAgentId: 'agent-a',
      targetAgentId: 'agent-b',
      message: { role: 'user', content: 'Analyze this data' },
    });

    expect(task.id).toBe('task-001');
    expect(task.sourceAgentId).toBe('agent-a');
    expect(task.targetAgentId).toBe('agent-b');
    expect(task.status).toBe('completed');
    expect(task.message).toEqual({ role: 'user', content: 'Analyze this data' });
    expect(task.artifacts).toHaveLength(1);
    expect(task.createdAt).toBe('2026-02-01T00:00:00Z');

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/a2a',
      expect.objectContaining({ method: 'POST' }),
    );

    const callBody = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(callBody.jsonrpc).toBe('2.0');
    expect(callBody.method).toBe('tasks/send');
    expect(callBody.params.source_agent_id).toBe('agent-a');
    expect(callBody.params.target_agent_id).toBe('agent-b');
    expect(callBody.id).toBeDefined();
  });

  it('sends a message via A2A v1.0 message/send', async () => {
    const v1Task = {
      id: 'task-v1-001',
      contextId: 'ctx-001',
      status: { state: 'completed', timestamp: '2026-02-01T00:01:00Z' },
      history: [{ role: 'user', parts: [{ kind: 'text', text: 'Hello there' }] }],
      artifacts: [{ artifactId: 'art-1', parts: [{ kind: 'text', text: 'Hi!' }] }],
    };
    mockFetch.mockReturnValueOnce(jsonResponse({
      jsonrpc: '2.0',
      result: v1Task,
      id: '1',
    }));

    const task = await client.a2a.sendMessage('agent-b', {
      text: 'Hello there',
      messageId: 'msg-123',
    });

    expect(task.id).toBe('task-v1-001');
    expect(task.contextId).toBe('ctx-001');
    expect(task.status.state).toBe('completed');
    expect(task.status.timestamp).toBe('2026-02-01T00:01:00Z');
    expect(task.history).toHaveLength(1);
    expect(task.artifacts).toHaveLength(1);

    // Posts to the per-agent A2A endpoint
    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/a2a/agents/agent-b',
      expect.objectContaining({ method: 'POST' }),
    );

    const callBody = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(callBody.jsonrpc).toBe('2.0');
    expect(callBody.method).toBe('message/send');
    expect(callBody.params.message.role).toBe('user');
    expect(callBody.params.message.parts).toEqual([{ kind: 'text', text: 'Hello there' }]);
    expect(callBody.params.message.messageId).toBe('msg-123');
    expect(callBody.params.message.taskId).toBeUndefined();
    expect(callBody.id).toBeDefined();
  });

  it('generates a messageId and includes taskId when provided', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      jsonrpc: '2.0',
      result: { id: 'task-v1-002', contextId: 'ctx-002', status: { state: 'working' } },
      id: '1',
    }));

    const task = await client.a2a.sendMessage('agent-c', {
      text: 'Continue',
      taskId: 'task-v1-001',
    });

    expect(task.id).toBe('task-v1-002');
    expect(task.status.state).toBe('working');

    const callBody = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(callBody.params.message.taskId).toBe('task-v1-001');
    expect(typeof callBody.params.message.messageId).toBe('string');
    expect(callBody.params.message.messageId.length).toBeGreaterThan(0);
  });

  it('gets a task via JSON-RPC', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      jsonrpc: '2.0',
      result: mockTask,
      id: '2',
    }));

    const task = await client.a2a.getTask('task-001');

    expect(task.id).toBe('task-001');
    expect(task.status).toBe('completed');

    const callBody = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(callBody.method).toBe('tasks/get');
    expect(callBody.params.id).toBe('task-001');
  });

  it('cancels a task via JSON-RPC', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      jsonrpc: '2.0',
      result: { ...mockTask, status: 'canceled' },
      id: '3',
    }));

    const task = await client.a2a.cancelTask('task-001');

    expect(task.status).toBe('canceled');

    const callBody = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(callBody.method).toBe('tasks/cancel');
    expect(callBody.params.id).toBe('task-001');
  });

  it('throws AgentTrustError on JSON-RPC error response', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      jsonrpc: '2.0',
      error: { code: -32600, message: 'Invalid request' },
      id: '4',
    }));

    await expect(client.a2a.getTask('bad-task')).rejects.toThrow(AgentTrustError);
    await expect(client.a2a.getTask('bad-task')).rejects.toBeTruthy();
  });

  it('increments request IDs', async () => {
    // Create a fresh client so the A2A counter starts at 0
    const freshClient = new AgentTrustClient({ baseUrl: 'http://localhost:8080', apiKey: 'sk_test' });

    mockFetch.mockReturnValueOnce(jsonResponse({ jsonrpc: '2.0', result: mockTask, id: '1' }));
    mockFetch.mockReturnValueOnce(jsonResponse({ jsonrpc: '2.0', result: mockTask, id: '2' }));

    await freshClient.a2a.getTask('task-1');
    await freshClient.a2a.getTask('task-2');

    const body1 = JSON.parse(mockFetch.mock.calls[0][1].body);
    const body2 = JSON.parse(mockFetch.mock.calls[1][1].body);
    expect(Number(body1.id)).toBeLessThan(Number(body2.id));
  });
});

describe('MCPAPI', () => {
  const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080', apiKey: 'sk_test' });

  const mockServer = {
    id: 'mcp-srv-1',
    name: 'filesystem',
    url: 'http://localhost:3001',
    capabilities: ['read', 'write'],
    org_id: 'org-1',
    created_at: '2026-02-01T00:00:00Z',
  };

  it('registers a server', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse(mockServer));

    const server = await client.mcp.registerServer({
      name: 'filesystem',
      url: 'http://localhost:3001',
      capabilities: ['read', 'write'],
    });

    expect(server.id).toBe('mcp-srv-1');
    expect(server.name).toBe('filesystem');
    expect(server.url).toBe('http://localhost:3001');
    expect(server.capabilities).toEqual(['read', 'write']);
    expect(server.orgId).toBe('org-1');

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/mcp/servers',
      expect.objectContaining({ method: 'POST' }),
    );

    const callBody = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(callBody.name).toBe('filesystem');
    expect(callBody.url).toBe('http://localhost:3001');
    expect(callBody.capabilities).toEqual(['read', 'write']);
  });

  it('lists servers', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      servers: [mockServer, { ...mockServer, id: 'mcp-srv-2', name: 'database' }],
    }));

    const servers = await client.mcp.listServers();

    expect(servers).toHaveLength(2);
    expect(servers[0].name).toBe('filesystem');
    expect(servers[1].name).toBe('database');

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/mcp/servers',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('handles array response for listServers', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse([mockServer]));

    const servers = await client.mcp.listServers();
    expect(servers).toHaveLength(1);
    expect(servers[0].id).toBe('mcp-srv-1');
  });

  it('removes a server', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({}));

    await client.mcp.removeServer('mcp-srv-1');

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/mcp/servers/mcp-srv-1',
      expect.objectContaining({ method: 'DELETE' }),
    );
  });

  it('calls a tool on a server', async () => {
    let capturedHeaders: Record<string, string> = {};
    mockFetch.mockImplementationOnce((url: string, init: { headers: Record<string, string> }) => {
      capturedHeaders = { ...init.headers };
      return jsonResponse({ result: { files: ['a.txt', 'b.txt'] } });
    });

    const result = await client.mcp.callTool('mcp-srv-1', 'agent-1', 'list_files', { path: '/tmp' });

    expect(result).toEqual({ files: ['a.txt', 'b.txt'] });
    expect(capturedHeaders['X-Agent-ID']).toBe('agent-1');

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/mcp/mcp-srv-1',
      expect.objectContaining({ method: 'POST' }),
    );

    const callBody = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(callBody.jsonrpc).toBe('2.0');
    expect(callBody.method).toBe('list_files');
    expect(callBody.params).toEqual({ path: '/tmp' });
  });
});

describe('DelegationsAPI', () => {
  const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080', apiKey: 'sk_test' });

  const mockDelegation = {
    id: 'del-001',
    from_agent_id: 'agent-a',
    to_agent_id: 'agent-b',
    scope: ['files:read', 'files:write'],
    restrictions: { max_file_size: 1024 },
    delegation_chain: ['del-000'],
    expires_at: '2026-03-01T00:00:00Z',
    created_at: '2026-02-01T00:00:00Z',
  };

  it('creates a delegation', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({ delegation: mockDelegation }));

    const delegation = await client.delegations.create({
      fromAgentId: 'agent-a',
      toAgentId: 'agent-b',
      scope: ['files:read', 'files:write'],
      ttlSeconds: 3600,
      restrictions: { max_file_size: 1024 },
    });

    expect(delegation.id).toBe('del-001');
    expect(delegation.fromAgentId).toBe('agent-a');
    expect(delegation.toAgentId).toBe('agent-b');
    expect(delegation.scope).toEqual(['files:read', 'files:write']);
    expect(delegation.restrictions).toEqual({ max_file_size: 1024 });
    expect(delegation.delegationChain).toEqual(['del-000']);
    expect(delegation.expiresAt).toBe('2026-03-01T00:00:00Z');
    expect(delegation.createdAt).toBe('2026-02-01T00:00:00Z');

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/api/v1/delegations',
      expect.objectContaining({ method: 'POST' }),
    );

    const callBody = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(callBody.from_agent_id).toBe('agent-a');
    expect(callBody.to_agent_id).toBe('agent-b');
    expect(callBody.scope).toEqual(['files:read', 'files:write']);
    expect(callBody.ttl_seconds).toBe(3600);
    expect(callBody.restrictions).toEqual({ max_file_size: 1024 });
  });

  it('creates a delegation with parent delegation ID', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      ...mockDelegation,
      delegation_chain: ['del-000', 'del-001'],
    }));

    const delegation = await client.delegations.create({
      fromAgentId: 'agent-a',
      toAgentId: 'agent-c',
      scope: ['files:read'],
      parentDelegationId: 'del-001',
    });

    const callBody = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(callBody.parent_delegation_id).toBe('del-001');
    expect(delegation.delegationChain).toEqual(['del-000', 'del-001']);
  });

  it('lists delegations', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      delegations: [
        mockDelegation,
        { ...mockDelegation, id: 'del-002', scope: ['search'] },
      ],
    }));

    const delegations = await client.delegations.list();

    expect(delegations).toHaveLength(2);
    expect(delegations[0].id).toBe('del-001');
    expect(delegations[1].id).toBe('del-002');

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/api/v1/delegations',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('handles array response for list', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse([mockDelegation]));

    const delegations = await client.delegations.list();
    expect(delegations).toHaveLength(1);
    expect(delegations[0].id).toBe('del-001');
  });

  it('revokes a delegation', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({}));

    await client.delegations.revoke('del-001');

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/api/v1/delegations/del-001',
      expect.objectContaining({ method: 'DELETE' }),
    );
  });

  it('initializes a delegated session', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      session_id: 'sess-del-001',
      agent_id: 'agent-b',
      delegation_id: 'del-001',
      source: 'a2a',
      mode: 'read_only',
      scope_ceiling: ['files:read'],
    }));

    const session = await client.delegations.initSession('del-001');

    expect(session.sessionId).toBe('sess-del-001');
    expect(session.delegationId).toBe('del-001');
    expect(session.source).toBe('a2a');

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/api/v1/delegations/del-001/session',
      expect.objectContaining({ method: 'POST' }),
    );
  });
});

describe('FederationAPI', () => {
  const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080', apiKey: 'sk_test' });

  it('registers and lists providers', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      provider: {
        id: 'prov-001',
        org_id: 'org-001',
        issuer: 'https://issuer.example.com',
        name: 'Example Issuer',
        jwks_uri: 'https://issuer.example.com/jwks',
        trust_level: 'high',
        status: 'active',
      },
    }));

    const provider = await client.federation.registerProvider({
      issuer: 'https://issuer.example.com',
      name: 'Example Issuer',
      trustLevel: 'high',
    });

    expect(provider.id).toBe('prov-001');
    expect(provider.trustLevel).toBe('high');

    mockFetch.mockReturnValueOnce(jsonResponse({
      providers: [
        {
          id: 'prov-001',
          org_id: 'org-001',
          issuer: 'https://issuer.example.com',
          name: 'Example Issuer',
          jwks_uri: 'https://issuer.example.com/jwks',
          trust_level: 'high',
          status: 'active',
        },
      ],
    }));

    const providers = await client.federation.listProviders();
    expect(providers).toHaveLength(1);
    expect(providers[0].issuer).toBe('https://issuer.example.com');
  });

  it('verifies a federated token and initializes a session', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      valid: true,
      agent_id: 'agent-remote-1',
      issuer: 'https://issuer.example.com',
      expires_at: '2026-03-01T10:15:00Z',
    }));

    const verification = await client.federation.verifyToken({
      token: 'eyJ.federated-token',
    });
    expect(verification.agentId).toBe('agent-remote-1');

    mockFetch.mockReturnValueOnce(jsonResponse({
      session_id: 'sess-fed-001',
      agent_id: 'agent-remote-1',
      provider_id: 'prov-001',
      issuer: 'https://issuer.example.com',
      trust_level: 'high',
      source: 'federation',
      mode: 'read_only',
      scope_ceiling: ['federation:invoke'],
    }));

    const session = await client.federation.initSession({
      token: 'eyJ.federated-token',
    });

    expect(session.sessionId).toBe('sess-fed-001');
    expect(session.providerId).toBe('prov-001');
    expect(session.trustLevel).toBe('high');
  });
});

describe('StreamingAPI', () => {
  const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080', apiKey: 'sk_test' });

  it('creates, updates, lists, and tests SIEM destinations', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      id: 'dest-001',
      name: 'Splunk Prod',
      destination_type: 'splunk_hec',
      endpoint_url: 'https://splunk.example.com',
      is_active: true,
      batch_size: 100,
      flush_interval_seconds: 30,
    }));

    const destination = await client.streaming.create({
      name: 'Splunk Prod',
      destinationType: 'splunk_hec',
      endpointUrl: 'https://splunk.example.com',
    });
    expect(destination.id).toBe('dest-001');

    mockFetch.mockReturnValueOnce(jsonResponse({
      id: 'dest-001',
      name: 'Splunk Prod 2',
      destination_type: 'splunk_hec',
      endpoint_url: 'https://splunk.example.com',
      is_active: false,
      batch_size: 200,
      flush_interval_seconds: 15,
    }));
    const updated = await client.streaming.update('dest-001', { name: 'Splunk Prod 2', isActive: false });
    expect(updated.name).toBe('Splunk Prod 2');

    mockFetch.mockReturnValueOnce(jsonResponse({
      destinations: [
        {
          id: 'dest-001',
          name: 'Splunk Prod 2',
          destination_type: 'splunk_hec',
          endpoint_url: 'https://splunk.example.com',
          is_active: false,
          batch_size: 200,
          flush_interval_seconds: 15,
        },
      ],
    }));
    const destinations = await client.streaming.list();
    expect(destinations).toHaveLength(1);

    mockFetch.mockReturnValueOnce(jsonResponse({
      logs: [
        {
          id: 'log-001',
          destination_id: 'dest-001',
          batch_size: 50,
          status: 'success',
          delivered_at: '2026-03-01T10:00:00Z',
        },
      ],
    }));
    const logs = await client.streaming.deliveryLog('dest-001');
    expect(logs[0].destinationId).toBe('dest-001');

    mockFetch.mockReturnValueOnce(jsonResponse({ success: true }));
    const result = await client.streaming.test('dest-001');
    expect(result.success).toBe(true);
  });
});

describe('AgentTrustClient protocol properties', () => {
  it('exposes all new protocol APIs', () => {
    const client = new AgentTrustClient();
    expect(client.agentCards).toBeDefined();
    expect(client.a2a).toBeDefined();
    expect(client.mcp).toBeDefined();
    expect(client.delegations).toBeDefined();
    expect(client.federation).toBeDefined();
    expect(client.streaming).toBeDefined();
  });
});
