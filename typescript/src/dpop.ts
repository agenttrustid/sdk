/**
 * RFC 9449 DPoP proof minting.
 *
 * Produces the exact JOSE shape the platform verifies, signed with the agent's
 * Ed25519 key (dependency-free, using Node crypto — consistent with the SDK's
 * existing proof-of-possession signing):
 *
 *   header:  { "typ":"dpop+jwt", "alg":"EdDSA", "jwk":{ "kty":"OKP","crv":"Ed25519","x":... } }
 *   payload: { "htm","htu","iat","jti","ath"? }
 *
 * The platform verifies the signature against the embedded JWK and checks the
 * key's thumbprint against the access token's RFC 7800 cnf.jkt.
 */
import { createHash, createPrivateKey, createPublicKey, randomBytes, KeyObject } from 'crypto';
import { KeyStore, signWithPrivateKeyPem } from './keys';

type Jwk = { kty: string; crv: string; x: string };
type Signer = (input: Buffer) => Buffer;

function b64url(data: Uint8Array): string {
  return Buffer.from(data).toString('base64url');
}

function publicJwk(key: KeyObject): Jwk {
  const jwk = key.export({ format: 'jwk' }) as { kty?: string; crv?: string; x?: string };
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.x) {
    throw new Error('not an Ed25519 public key');
  }
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x };
}

function buildProof(jwk: Jwk, sign: Signer, method: string, url: string, accessToken: string): string {
  const header = { typ: 'dpop+jwt', alg: 'EdDSA', jwk };
  const payload: Record<string, unknown> = {
    htm: method,
    htu: url,
    iat: Math.floor(Date.now() / 1000),
    jti: randomBytes(16).toString('hex'),
  };
  if (accessToken) {
    payload.ath = createHash('sha256').update(accessToken).digest().toString('base64url');
  }
  const signingInput =
    b64url(Buffer.from(JSON.stringify(header))) + '.' + b64url(Buffer.from(JSON.stringify(payload)));
  const sig = sign(Buffer.from(signingInput));
  return signingInput + '.' + b64url(sig);
}

/** Mint a DPoP proof signed with the agent's Ed25519 private key (PKCS#8 PEM). */
export function mintDPoPProof(privateKeyPem: string, method: string, url: string, accessToken: string): string {
  const pub = publicJwk(createPublicKey(createPrivateKey(privateKeyPem)));
  return buildProof(pub, (input) => signWithPrivateKeyPem(privateKeyPem, input), method, url, accessToken);
}

/**
 * Mint a DPoP proof signing through a KeyStore, so the private key stays
 * non-exportable; only the public key (PKIX PEM) is handled in the clear.
 */
export function mintDPoPProofWithKeyStore(
  ks: KeyStore,
  agentId: string,
  publicKeyPem: string,
  method: string,
  url: string,
  accessToken: string,
): string {
  const pub = publicJwk(createPublicKey(publicKeyPem));
  return buildProof(pub, (input) => ks.sign(agentId, input), method, url, accessToken);
}
