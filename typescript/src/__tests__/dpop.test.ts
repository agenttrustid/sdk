import { createHash, createPublicKey, verify } from 'crypto';
import { generateAgentKey, MemoryKeyStore } from '../keys';
import { mintDPoPProof, mintDPoPProofWithKeyStore } from '../dpop';

const CHECK_URL = 'https://api.agenttrust.id/api/v1/agenttrust/check';

function parseProof(proof: string) {
  const [h, p, s] = proof.split('.');
  return {
    header: JSON.parse(Buffer.from(h, 'base64url').toString()),
    payload: JSON.parse(Buffer.from(p, 'base64url').toString()),
    signingInput: `${h}.${p}`,
    sig: Buffer.from(s, 'base64url'),
  };
}

function verifyProof(proof: string): boolean {
  const { header, signingInput, sig } = parseProof(proof);
  const pub = createPublicKey({ key: header.jwk, format: 'jwk' });
  return verify(null, Buffer.from(signingInput), pub, sig);
}

describe('mintDPoPProof', () => {
  it('produces a verifiable proof with the platform-expected claims', () => {
    const kp = generateAgentKey();
    const proof = mintDPoPProof(kp.privateKeyPem, 'POST', CHECK_URL, 'access-tok');
    const { header, payload } = parseProof(proof);

    expect(header.typ).toBe('dpop+jwt');
    expect(header.alg).toBe('EdDSA');
    expect(header.jwk.kty).toBe('OKP');
    expect(header.jwk.crv).toBe('Ed25519');
    expect(header.jwk.x).toBeTruthy();

    expect(payload.htm).toBe('POST');
    expect(payload.htu).toBe(CHECK_URL);
    expect(typeof payload.iat).toBe('number');
    expect(payload.jti).toBeTruthy();
    expect(payload.ath).toBe(createHash('sha256').update('access-tok').digest().toString('base64url'));

    expect(verifyProof(proof)).toBe(true);
  });

  it('omits ath when no access token is bound', () => {
    const kp = generateAgentKey();
    const { payload } = parseProof(mintDPoPProof(kp.privateKeyPem, 'GET', 'https://x/y', ''));
    expect(payload.ath).toBeUndefined();
  });

  it('mints unique jti per call', () => {
    const kp = generateAgentKey();
    const a = parseProof(mintDPoPProof(kp.privateKeyPem, 'POST', CHECK_URL, 'tok'));
    const b = parseProof(mintDPoPProof(kp.privateKeyPem, 'POST', CHECK_URL, 'tok'));
    expect(a.payload.jti).not.toBe(b.payload.jti);
  });

  it('rejects a non-Ed25519 key path gracefully', () => {
    expect(() => mintDPoPProof('-----BEGIN PRIVATE KEY-----\nbogus\n-----END PRIVATE KEY-----', 'POST', CHECK_URL, '')).toThrow();
  });
});

describe('mintDPoPProofWithKeyStore', () => {
  it('signs through the KeyStore and verifies against the embedded jwk', () => {
    const kp = generateAgentKey();
    const ks = new MemoryKeyStore();
    ks.store('agent-1', kp.privateKeyPem);

    const proof = mintDPoPProofWithKeyStore(ks, 'agent-1', kp.publicKeyPem, 'POST', CHECK_URL, 'tok');
    expect(verifyProof(proof)).toBe(true);
  });
});
