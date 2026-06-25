/**
 * AgentCard proof-of-possession binding helpers.
 *
 * A card's platform JWS proves AgentTrust ID vouched for the profile; it does
 * not prove the presenter controls the agent's key. The card embeds the agent's
 * registered Ed25519 public key as a JWK (`ati_agent_key`) in the trust
 * extension, so a verifier can extract it (after verifying the platform JWS) and
 * challenge the holder to sign a nonce — turning the card into a passport that
 * must be proven, not just presented.
 */
import { createPublicKey } from 'crypto';
import { AgentCard } from './types';

const TRUST_EXTENSION_URI = 'https://agenttrust.id/ext/trust/v1';

/**
 * Extracts the agent's registered Ed25519 public key (PKIX/SPKI PEM) from a
 * fetched card's trust extension (`ati_agent_key`), or `undefined` if the card
 * predates the PoP binding. Verify the card's platform JWS first — that is what
 * makes this key authoritative.
 */
export function agentPublicKeyFromCard(card: AgentCard): string | undefined {
  const ext = card.capabilities?.extensions?.find((e) => e.uri === TRUST_EXTENSION_URI);
  const jwk = ext?.params?.['ati_agent_key'] as
    | { kty?: string; crv?: string; x?: string }
    | undefined;
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string' || !jwk.x) {
    return undefined;
  }
  try {
    const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, format: 'jwk' });
    return key.export({ type: 'spki', format: 'pem' }) as string;
  } catch {
    return undefined;
  }
}
