import { createPublicKey } from 'crypto';
import { generateAgentKey } from '../keys';
import { agentPublicKeyFromCard } from '../agentcard';
import { AgentCard } from '../types';

const TRUST_URI = 'https://agenttrust.id/ext/trust/v1';

function xFromPem(pem: string): string {
  const jwk = createPublicKey(pem).export({ format: 'jwk' }) as { x: string };
  return jwk.x;
}

function cardWith(params: Record<string, unknown>): AgentCard {
  return {
    name: 'a',
    version: '1.0.0',
    capabilities: { streaming: false, pushNotifications: false, extensions: [{ uri: TRUST_URI, params }] },
    skills: [],
  } as AgentCard;
}

describe('agentPublicKeyFromCard', () => {
  it('extracts the embedded key as the original PKIX PEM', () => {
    const kp = generateAgentKey();
    const card = cardWith({ ati_agent_key: { kty: 'OKP', crv: 'Ed25519', x: xFromPem(kp.publicKeyPem) } });
    const pem = agentPublicKeyFromCard(card);
    expect(pem).toBeDefined();
    expect(pem!.trim()).toBe(kp.publicKeyPem.trim());
  });

  it('returns undefined when the card has no ati_agent_key', () => {
    expect(agentPublicKeyFromCard(cardWith({ ati_trust_score: 0.5 }))).toBeUndefined();
    expect(agentPublicKeyFromCard({ name: 'a', version: '1', capabilities: { streaming: false, pushNotifications: false }, skills: [] } as AgentCard)).toBeUndefined();
  });

  it('returns undefined for a malformed key', () => {
    expect(agentPublicKeyFromCard(cardWith({ ati_agent_key: { kty: 'OKP', crv: 'Ed25519', x: 'not base64!!' } }))).toBeUndefined();
    expect(agentPublicKeyFromCard(cardWith({ ati_agent_key: { kty: 'RSA' } }))).toBeUndefined();
  });
});
