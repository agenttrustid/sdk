/**
 * Narrated, end-to-end proof that AgentTrust ID's runtime authorization is
 * sender-constrained: agent identity is proven by a key-bound WIMSE token plus a
 * per-request DPoP proof, not asserted in the request body. Runs against a REAL
 * gateway (no mocks) and demonstrates four properties, printing ✓/✗ for each.
 * Exits non-zero if any proof fails.
 *
 * Token order under test:
 *
 *   org API key ─▶ register agent (identity key) ─▶ PoP challenge ─▶
 *   WIMSE token (cnf.jkt) ─▶ per-request DPoP proof ─▶ /agenttrust/check
 *
 * Setup (local stack):
 *
 *   export AGENTTRUST_URL=http://localhost:8080     # gateway
 *   export AGENTTRUST_API_KEY=sk_live_...           # an ORG ADMIN key
 *   # The gateway/auth-service MUST run with BASE_URL=http://localhost:8080 so the
 *   # DPoP `htu` the server rebuilds matches the URL the SDK signs. If they differ,
 *   # even the legitimate check fails with a DPoP URL error.
 *   cd sdk/typescript && npm run build && npm i -D tsx && npx tsx examples/dpop-proof.ts
 *
 * PRECONDITION: enable the org's enforcement toggle first, in the dashboard at
 * Settings → Security → "Require sender-constrained tokens (DPoP)" (that setting
 * is admin/session-gated, so the demo can't flip it with an API key). The demo
 * detects whether it is on and tells you if it isn't.
 */
import {
  AgentTrustClient,
  AgentCredentials,
  MemoryKeyStore,
  generateAgentKey,
  mintDPoPProof,
  mintDPoPProofWithKeyStore,
} from '../src';

const BASE_URL = process.env.AGENTTRUST_URL || 'http://localhost:8080';
const ADMIN_KEY = process.env.AGENTTRUST_API_KEY || '';
const CHECK_PATH = '/api/v1/agenttrust/check';

let failures = 0;

const banner = (s: string) => console.log(`\n══ ${s} ══`);
const section = (s: string) => console.log(`\n── ${s} ──`);
const ok = (msg: string) => console.log(`  ✓ ${msg}`);
const bad = (msg: string) => {
  failures++;
  console.log(`  ✗ ${msg}`);
};
function fatal(msg: string): never {
  console.log(`\nFATAL: ${msg}`);
  process.exit(2);
}

/** Simulate a non-SDK caller (attacker/replay): hand-build the request. */
async function rawCheck(bearer: string, dpop: string, bodyAgentId: string): Promise<number> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-API-Key': ADMIN_KEY,
  };
  if (bearer) headers['Authorization'] = `Bearer ${bearer}`;
  if (dpop) headers['DPoP'] = dpop;
  const resp = await fetch(BASE_URL + CHECK_PATH, {
    method: 'POST',
    headers,
    body: JSON.stringify({ agent_id: bodyAgentId, action_name: 'read_file', action_source: 'api' }),
  });
  return resp.status;
}

function expectRejected(label: string, status: number): void {
  if (status === 401 || status === 403) ok(`${label} ⇒ rejected (HTTP ${status})`);
  else bad(`${label} ⇒ NOT rejected (HTTP ${status})`);
}

async function createAgent(client: AgentTrustClient, name: string) {
  const agent = await client.agents.create({ name: `${name}-${Date.now()}`, framework: 'custom' });
  if (!agent.privateKey) fatal(`agent ${name} returned no private key`);
  return agent;
}

async function main() {
  if (!ADMIN_KEY) fatal('set AGENTTRUST_API_KEY to an org admin key (sk_live_...)');

  banner('AgentTrust ID — sender-constrained runtime auth proof');
  console.log(`  gateway: ${BASE_URL}`);
  console.log(
    [
      '',
      '  Token order under test:',
      '    1. org API key          who is the ORGANISATION (X-API-Key, control plane)',
      '    2. agent identity key   who is the AGENT (client-held Ed25519; only the public half is registered)',
      '    3. PoP challenge        single-use nonce proving the agent holds its key',
      '    4. WIMSE token          short-lived JWT bound to the agent key via cnf.jkt',
      '    5. DPoP proof           per-request signature proving key possession on THIS call',
    ].join('\n'),
  );

  const client = new AgentTrustClient({ baseUrl: BASE_URL, apiKey: ADMIN_KEY });

  section('Provision: register agents (steps 1–4 of the token order)');
  const agentA = await createAgent(client, 'dpop-proof-A');
  const agentB = await createAgent(client, 'dpop-proof-B');
  console.log(`  agent A ${agentA.id} — public key registered, private key kept locally`);
  console.log(`  agent B ${agentB.id} — a second agent in the same org (for the spoof test)`);

  const ks = new MemoryKeyStore();
  ks.store(agentA.id, agentA.privateKey!);
  const creds = new AgentCredentials(client, ks, agentA.id, agentA.publicKey);
  client.useAgentCredentials(creds);

  const tokenA = await creds.token(); // challenge → sign → issue, cached
  console.log(`  step 4: WIMSE token issued for A (cnf.jkt-bound): ${tokenA.slice(0, 18)}…`);

  // Precondition: the org must enforce sender-constrained tokens, else the
  // rejection proofs can't fire. Detect it behaviorally (bearer, no DPoP proof):
  // rejected ⇒ enforcement on; accepted ⇒ the toggle is still off.
  section('Precondition: org enforces sender-constrained tokens');
  const pre = await rawCheck(tokenA, '', agentA.id);
  if (pre === 401 || pre === 403) {
    ok(`enforcement is ON (bearer without a DPoP proof is rejected, HTTP ${pre})`);
  } else {
    fatal(
      `enforcement is OFF (bearer without DPoP returned HTTP ${pre}).\n` +
        '  Enable Settings → Security → "Require sender-constrained tokens (DPoP)" for this org, then re-run.',
    );
  }

  // PROOF 1
  section('PROOF 1 — legitimate agent: WIMSE bearer + DPoP ⇒ accepted');
  try {
    await client.actions.check({ agentId: agentA.id, toolName: 'read_file' });
    ok('check authenticated and evaluated (step 5 DPoP proof verified against cnf.jkt)');
  } catch (e) {
    bad(`legitimate check rejected: ${e}`);
    console.log(`  hint: if this is a DPoP URL error, run the gateway with BASE_URL=${BASE_URL}`);
  }

  // PROOF 2
  section('PROOF 2 — stolen token without the key ⇒ rejected');
  expectRejected('2a: replayed bearer, no DPoP proof', await rawCheck(tokenA, '', agentA.id));
  const attacker = generateAgentKey();
  const forged = mintDPoPProof(attacker.privateKeyPem, 'POST', BASE_URL + CHECK_PATH, tokenA);
  expectRejected(
    '2b: bearer + DPoP signed by a different key (cnf.jkt mismatch)',
    await rawCheck(tokenA, forged, agentA.id),
  );

  // PROOF 3
  section('PROOF 3 — body says agent B, token proves agent A ⇒ rejected');
  try {
    await client.actions.check({ agentId: agentB.id, toolName: 'read_file' });
    bad('body agent_id spoof was ACCEPTED (identity trusted from body)');
  } catch (e) {
    ok(`body agent_id=B with A's proof rejected — identity comes from the token: ${e}`);
  }

  // PROOF 4
  section('PROOF 4 — DPoP proof replay ⇒ rejected');
  const proof = mintDPoPProofWithKeyStore(
    ks,
    agentA.id,
    agentA.publicKey,
    'POST',
    BASE_URL + CHECK_PATH,
    tokenA,
  );
  const st1 = await rawCheck(tokenA, proof, agentA.id);
  const st2 = await rawCheck(tokenA, proof, agentA.id); // same jti again
  if (st1 >= 200 && st1 < 300 && (st2 === 401 || st2 === 403)) {
    ok(`first use accepted (HTTP ${st1}), identical proof replayed ⇒ rejected (HTTP ${st2})`);
  } else {
    bad(`replay not prevented: first=${st1} second=${st2} (want 2xx then 401/403)`);
  }

  banner('Result');
  if (failures === 0) {
    console.log('  ✓ all proofs passed — runtime auth is sender-constrained and token-derived');
    process.exit(0);
  }
  console.log(`  ✗ ${failures} proof(s) failed`);
  process.exit(1);
}

main().catch((e) => fatal(String(e)));
