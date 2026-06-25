import { createPublicKey, verify as edVerify } from 'crypto';
import { AgentTrustClient } from '../client';
import { generateAgentKey, MemoryKeyStore } from '../keys';

// Mock fetch globally.
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

describe('WIMSEAPI', () => {
  it('issues a token and maps snake_case response', async () => {
    mockFetch.mockReturnValueOnce(
      jsonResponse({
        token: 'eyJ.t',
        workload_id: 'spiffe://ati/agent/a1',
        trust_domain: 'agenttrust.id',
        expires_at: '2026-12-31T00:00:00Z',
      }),
    );
    const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080' });
    const resp = await client.wimse.issueToken({ agentId: 'a1', serviceName: 'payments' });
    expect(resp.token).toBe('eyJ.t');
    expect(resp.workloadId).toBe('spiffe://ati/agent/a1');
    const [, init] = mockFetch.mock.calls[0];
    expect(JSON.parse(init.body)).toEqual({ agent_id: 'a1', service_name: 'payments' });
  });

  it('verifies a token', async () => {
    mockFetch.mockReturnValueOnce(
      jsonResponse({ valid: true, agent_id: 'a1', capabilities: ['x', 'y'] }),
    );
    const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080' });
    const resp = await client.wimse.verifyToken({ token: 'eyJ.t' });
    expect(resp.valid).toBe(true);
    expect(resp.agentId).toBe('a1');
    expect(resp.capabilities).toHaveLength(2);
  });

  it('performs challenge -> sign -> issue and sends a verifiable proof', async () => {
    const kp = generateAgentKey();
    const ks = new MemoryKeyStore();
    ks.store('a1', kp.privateKeyPem);

    const nonce = 'server-nonce-xyz';
    const audience = ['https://api.example.com'];

    // 1st call: challenge. 2nd call: issue token.
    mockFetch
      .mockReturnValueOnce(jsonResponse({ nonce, expires_at: '2026-12-31T00:00:00Z' }))
      .mockReturnValueOnce(jsonResponse({ token: 'eyJ.bound', trust_domain: 'agenttrust.id' }));

    const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080' });
    const resp = await client.wimse.issueTokenWithProof({ agentId: 'a1', audience }, ks);
    expect(resp.token).toBe('eyJ.bound');

    // The challenge endpoint was hit first.
    expect(mockFetch.mock.calls[0][0]).toBe('http://localhost:8080/api/v1/agents/a1/challenge');

    // Inspect the proof sent on the issue call.
    const issueBody = JSON.parse(mockFetch.mock.calls[1][1].body);
    expect(issueBody.proof.nonce).toBe(nonce);

    // Reconstruct the canonical message and verify the signature with the
    // agent's public key — exactly what the server's VerifyPoP checks.
    const ts = issueBody.proof.ts as number;
    const message = `pop-v1:${nonce}:a1:${audience.join(',')}:${ts}`;
    const sig = Buffer.from(issueBody.proof.signature, 'base64url');
    const pubKey = createPublicKey(kp.publicKeyPem);
    const ok = edVerify(null, Buffer.from(message, 'utf8'), pubKey, sig);
    expect(ok).toBe(true);
  });
});
