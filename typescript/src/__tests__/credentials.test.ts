import { createPublicKey, verify as edVerify } from 'crypto';
import { AgentTrustClient, AgentCredentials } from '../client';
import { generateAgentKey, MemoryKeyStore } from '../keys';

const mockFetch = jest.fn();
global.fetch = mockFetch as unknown as typeof fetch;

beforeEach(() => mockFetch.mockReset());

function json(data: unknown, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(JSON.stringify(data)),
  });
}

interface Captured {
  tokenCalls: number;
  checkCalls: number;
  auth?: string;
  dpop?: string;
}

function routeFetch(tokenExpiresAt: string): Captured {
  const cap: Captured = { tokenCalls: 0, checkCalls: 0 };
  mockFetch.mockImplementation((url: string, init: { headers: Record<string, string> }) => {
    if (url.endsWith('/challenge')) {
      return json({ nonce: 'nonce-123', expires_at: new Date(Date.now() + 60_000).toISOString() });
    }
    if (url.endsWith('/api/v1/wimse/token')) {
      cap.tokenCalls++;
      return json({ token: 'wimse-tok', expires_at: tokenExpiresAt });
    }
    if (url.endsWith('/api/v1/agenttrust/check')) {
      cap.checkCalls++;
      cap.auth = init.headers['Authorization'];
      cap.dpop = init.headers['DPoP'];
      return json({ allowed: true, guard_tier: 'fast' });
    }
    return json({}, 404);
  });
  return cap;
}

function verifyDpop(proof: string): { ok: boolean; htu: string } {
  const [h, p, s] = proof.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url').toString());
  const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
  const pub = createPublicKey({ key: header.jwk, format: 'jwk' });
  const ok = edVerify(null, Buffer.from(`${h}.${p}`), pub, Buffer.from(s, 'base64url'));
  return { ok, htu: payload.htu };
}

function newCreds() {
  const kp = generateAgentKey();
  const ks = new MemoryKeyStore();
  ks.store('agent-1', kp.privateKeyPem);
  const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080' });
  const ac = new AgentCredentials(client, ks, 'agent-1', kp.publicKeyPem);
  return { client, ac };
}

describe('AgentCredentials', () => {
  it('issues, caches, and mints runtime headers', async () => {
    const cap = routeFetch(new Date(Date.now() + 3_600_000).toISOString());
    const { ac } = newCreds();

    expect(await ac.token()).toBe('wimse-tok');
    // Cached (~1h valid) — second call must not re-issue.
    await ac.token();
    expect(cap.tokenCalls).toBe(1);

    const headers = await ac.runtimeHeaders('POST', '/api/v1/agenttrust/check');
    expect(headers.Authorization).toBe('Bearer wimse-tok');
    expect(headers.DPoP).toBeTruthy();
    const { ok, htu } = verifyDpop(headers.DPoP);
    expect(ok).toBe(true);
    expect(htu).toBe('http://localhost:8080/api/v1/agenttrust/check');
  });

  it('refreshes the token when near expiry', async () => {
    // Expires in 10s — inside the 60s refresh skew — so each token() re-issues.
    const cap = routeFetch(new Date(Date.now() + 10_000).toISOString());
    const { ac } = newCreds();
    await ac.token();
    await ac.token();
    expect(cap.tokenCalls).toBe(2);
  });

  it('attaches Bearer + DPoP on actions.check when wired to the client', async () => {
    const cap = routeFetch(new Date(Date.now() + 3_600_000).toISOString());
    const { client, ac } = newCreds();
    client.useAgentCredentials(ac);

    const result = await client.actions.check({ agentId: 'agent-1', toolName: 'read_file' });
    expect(result.allowed).toBe(true);
    expect(cap.checkCalls).toBe(1);
    expect(cap.auth).toBe('Bearer wimse-tok');
    expect(cap.dpop).toBeTruthy();
    expect(verifyDpop(cap.dpop as string).ok).toBe(true);
  });

  it('re-issues after invalidate()', async () => {
    const cap = routeFetch(new Date(Date.now() + 3_600_000).toISOString());
    const { ac } = newCreds();
    await ac.token();
    ac.invalidate();
    await ac.token();
    expect(cap.tokenCalls).toBe(2);
  });
});
