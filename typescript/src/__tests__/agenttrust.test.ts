import { AgentTrustClient, AgentTrustGuard, SessionsAPI, ApprovalsAPI } from '../client';
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

const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080', apiKey: 'sk_test' });

// ---------------------------------------------------------------------------
// SessionsAPI
// ---------------------------------------------------------------------------

describe('SessionsAPI', () => {
  it('is initialized on AgentTrustClient', () => {
    expect(client.sessions).toBeInstanceOf(SessionsAPI);
  });

  it('initializes a session', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      session_id: 'sess-001',
      agent_id: 'agent-123',
      org_id: 'org-456',
      source: 'mcp',
      server_id: 'srv-001',
      mode: 'read_only',
      allowed_actions: ['files:read'],
      scope_ceiling: ['files:read', 'files:write'],
      total_calls: 0,
      read_calls: 0,
      write_calls: 0,
      denied_calls: 0,
      created_at: '2026-03-01T10:00:00Z',
    }));

    const session = await client.sessions.initSession('agent-123', 'srv-001');

    expect(session.sessionId).toBe('sess-001');
    expect(session.agentId).toBe('agent-123');
    expect(session.mode).toBe('read_only');
    expect(session.serverId).toBe('srv-001');
    expect(session.allowedActions).toEqual(['files:read']);
    expect(session.scopeCeiling).toEqual(['files:read', 'files:write']);
    expect(session.totalCalls).toBe(0);

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/mcp/sessions/init',
      expect.objectContaining({ method: 'POST' }),
    );
    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.agent_id).toBe('agent-123');
    expect(body.server_id).toBe('srv-001');
  });

  it('gets an existing session', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      session_id: 'sess-001',
      agent_id: 'agent-123',
      org_id: 'org-456',
      mode: 'elevated',
      total_calls: 5,
      read_calls: 3,
      write_calls: 2,
      denied_calls: 0,
    }));

    const session = await client.sessions.getSession('sess-001');

    expect(session.sessionId).toBe('sess-001');
    expect(session.mode).toBe('elevated');
    expect(session.totalCalls).toBe(5);
    expect(session.readCalls).toBe(3);
    expect(session.writeCalls).toBe(2);

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/mcp/sessions/sess-001',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('initializes an API-backed session', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      session_id: 'sess-api-001',
      agent_id: 'agent-123',
      source: 'api',
      mode: 'read_only',
      scope_ceiling: ['files:read'],
      created_at: '2026-03-01T10:00:00Z',
    }));

    const session = await client.sessions.initApiSession('eyJ.api-token');

    expect(session.sessionId).toBe('sess-api-001');
    expect(session.source).toBe('api');

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/api/v1/agenttrust/api-sessions/init',
      expect.objectContaining({ method: 'POST' }),
    );
    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.token).toBe('eyJ.api-token');
  });
});

// ---------------------------------------------------------------------------
// ApprovalsAPI
// ---------------------------------------------------------------------------

describe('ApprovalsAPI', () => {
  it('is initialized on AgentTrustClient', () => {
    expect(client.approvals).toBeInstanceOf(ApprovalsAPI);
  });

  it('approves an elevation request', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({ status: 'approved' }));

    await client.approvals.approve('apr-001', 'admin@example.com');

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/mcp/approvals/apr-001/approve',
      expect.objectContaining({ method: 'POST' }),
    );
    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.decided_by).toBe('admin@example.com');
  });

  it('denies an elevation request', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({ status: 'denied' }));

    await client.approvals.deny('apr-001', 'admin@example.com');

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/mcp/approvals/apr-001/deny',
      expect.objectContaining({ method: 'POST' }),
    );
    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.decided_by).toBe('admin@example.com');
  });

  it('gets an approval request', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      id: 'apr-001',
      session_id: 'sess-001',
      agent_id: 'agent-123',
      org_id: 'org-456',
      action_name: 'delete_file',
      action_effect: 'destructive',
      status: 'approved',
      decided_by: 'admin@example.com',
      created_at: '2026-03-01T10:00:00Z',
      expires_at: '2026-03-01T10:15:00Z',
    }));

    const approval = await client.approvals.get('apr-001');

    expect(approval.id).toBe('apr-001');
    expect(approval.sessionId).toBe('sess-001');
    expect(approval.actionName).toBe('delete_file');
    expect(approval.actionEffect).toBe('destructive');
    expect(approval.status).toBe('approved');
    expect(approval.decidedBy).toBe('admin@example.com');

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/mcp/approvals/apr-001',
      expect.objectContaining({ method: 'GET' }),
    );
  });
});

// ---------------------------------------------------------------------------
// ActionsAPI — action_effect and elevation response
// ---------------------------------------------------------------------------

describe('ActionsAPI — AgentTrust extensions', () => {
  it('sends action_effect in request', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({ allowed: true }));

    await client.actions.check({
      agentId: 'agent-123',
      toolName: 'write_file',
      actionEffect: 'mutating',
    });

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.action_effect).toBe('mutating');
  });

  it('omits action_effect when not provided', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({ allowed: true }));

    await client.actions.check({
      agentId: 'agent-123',
      toolName: 'read_file',
    });

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.action_effect).toBeUndefined();
  });

  it('parses elevation_required and approval_id', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      allowed: false,
      reason: 'session is read_only',
      elevation_required: true,
      approval_id: 'apr-001',
    }));

    const result = await client.actions.check({
      agentId: 'agent-123',
      toolName: 'delete_file',
      sessionId: 'sess-001',
    });

    expect(result.allowed).toBe(false);
    expect(result.elevationRequired).toBe(true);
    expect(result.approvalId).toBe('apr-001');
  });
});

// ---------------------------------------------------------------------------
// AgentTrustGuard — elevation handling
// ---------------------------------------------------------------------------

describe('AgentTrustGuard — elevation', () => {
  it('throws ELEVATION_REQUIRED when elevation needed', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      allowed: false,
      reason: 'session is read_only',
      elevation_required: true,
      approval_id: 'apr-001',
    }));

    const guard = new AgentTrustGuard(client, 'agent-1');

    try {
      await guard.check('delete_file');
      fail('expected error');
    } catch (err) {
      expect(err).toBeInstanceOf(AgentTrustError);
      const atiErr = err as AgentTrustError;
      expect(atiErr.code).toBe('ELEVATION_REQUIRED');
      expect(atiErr.details.approvalId).toBe('apr-001');
    }
  });

  it('throws ACTION_DENIED when denied without elevation', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      allowed: false,
      reason: 'capability not registered',
    }));

    const guard = new AgentTrustGuard(client, 'agent-1');

    try {
      await guard.check('forbidden_tool');
      fail('expected error');
    } catch (err) {
      expect(err).toBeInstanceOf(AgentTrustError);
      expect((err as AgentTrustError).code).toBe('ACTION_DENIED');
    }
  });

  it('passes actionEffect to actions.check', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({ allowed: true }));

    const guard = new AgentTrustGuard(client, 'agent-1');
    await guard.check('write_file', '', 'mutating');

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.action_effect).toBe('mutating');
  });

  it('returns false on elevation when blockOnDeny=false', async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({
      allowed: false,
      reason: 'needs elevation',
      elevation_required: true,
      approval_id: 'apr-002',
    }));

    const guard = new AgentTrustGuard(client, 'agent-1', { blockOnDeny: false });
    const result = await guard.check('write_file');
    expect(result).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// MCPAPI — sessionId in callTool
// ---------------------------------------------------------------------------

describe('MCPAPI — callTool with sessionId', () => {
  it('sets X-Session-ID header when sessionId provided', async () => {
    let capturedHeaders: Record<string, string> = {};
    mockFetch.mockImplementationOnce((url: string, init: { headers: Record<string, string> }) => {
      capturedHeaders = { ...init.headers };
      return jsonResponse({ result: { content: 'ok' } });
    });

    await client.mcp.callTool('srv-001', 'agent-1', 'tools/call', { name: 'read_file' }, 'sess-001');

    expect(capturedHeaders['X-Agent-ID']).toBe('agent-1');
    expect(capturedHeaders['X-Session-ID']).toBe('sess-001');
  });

  it('sets X-Agent-ID but not X-Session-ID when sessionId not provided', async () => {
    let capturedHeaders: Record<string, string> = {};
    mockFetch.mockImplementationOnce((url: string, init: { headers: Record<string, string> }) => {
      capturedHeaders = { ...init.headers };
      return jsonResponse({ result: {} });
    });

    await client.mcp.callTool('srv-001', 'agent-1', 'tools/list');

    expect(capturedHeaders['X-Agent-ID']).toBe('agent-1');
    expect(capturedHeaders['X-Session-ID']).toBeUndefined();
  });

  it('throws when agentId is missing', async () => {
    await expect(client.mcp.callTool('srv-001', '', 'tools/list')).rejects.toThrow(/agentId is required/);
  });
});
