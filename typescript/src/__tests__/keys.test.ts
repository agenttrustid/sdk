import { createPublicKey, verify as edVerify, generateKeyPairSync } from 'crypto';
import {
  generateAgentKey,
  signWithPrivateKeyPem,
  MemoryKeyStore,
  KeychainKeyStore,
} from '../keys';

// The native keychain library is optional and not installed; mock it virtually
// so the KeychainKeyStore logic runs in CI without a real OS keychain.
jest.mock(
  '@napi-rs/keyring',
  () => {
    const store = new Map<string, string>();
    return {
      Entry: class {
        constructor(private service: string, private account: string) {}
        private key(): string {
          return `${this.service}:${this.account}`;
        }
        setPassword(p: string): void {
          store.set(this.key(), p);
        }
        getPassword(): string {
          const v = store.get(this.key());
          if (v === undefined) throw new Error('password not found');
          return v;
        }
        deletePassword(): boolean {
          return store.delete(this.key());
        }
      },
    };
  },
  { virtual: true },
);

describe('generateAgentKey', () => {
  it('emits server-compatible PKIX/PKCS8 PEM', () => {
    const kp = generateAgentKey();
    expect(kp.publicKeyPem).toContain('-----BEGIN PUBLIC KEY-----');
    expect(kp.privateKeyPem).toContain('-----BEGIN PRIVATE KEY-----');
    expect(createPublicKey(kp.publicKeyPem).asymmetricKeyType).toBe('ed25519');
  });
});

describe('signWithPrivateKeyPem', () => {
  it('produces a signature that verifies against the public key', () => {
    const kp = generateAgentKey();
    const msg = Buffer.from('proof-of-possession challenge');
    const sig = signWithPrivateKeyPem(kp.privateKeyPem, msg);
    expect(edVerify(null, msg, createPublicKey(kp.publicKeyPem), sig)).toBe(true);
  });

  it('rejects a valid but non-Ed25519 key', () => {
    const { privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    expect(() => signWithPrivateKeyPem(privateKey as string, Buffer.from('x'))).toThrow();
  });
});

describe('MemoryKeyStore', () => {
  it('stores, signs, and deletes', () => {
    const kp = generateAgentKey();
    const ks = new MemoryKeyStore();
    ks.store('agt-1', kp.privateKeyPem);
    const sig = ks.sign('agt-1', Buffer.from('hello'));
    expect(edVerify(null, Buffer.from('hello'), createPublicKey(kp.publicKeyPem), sig)).toBe(true);
    ks.delete('agt-1');
    expect(() => ks.sign('agt-1', Buffer.from('hello'))).toThrow();
  });

  it('rejects an invalid key', () => {
    const ks = new MemoryKeyStore();
    expect(() => ks.store('agt', 'not-a-pem')).toThrow();
  });
});

describe('KeychainKeyStore', () => {
  it('stores, signs, and deletes via the native keychain (mocked)', () => {
    const kp = generateAgentKey();
    const ks = new KeychainKeyStore();
    ks.store('agt-1', kp.privateKeyPem);
    const sig = ks.sign('agt-1', Buffer.from('hello'));
    expect(edVerify(null, Buffer.from('hello'), createPublicKey(kp.publicKeyPem), sig)).toBe(true);
    ks.delete('agt-1');
    expect(() => ks.sign('agt-1', Buffer.from('hello'))).toThrow();
  });
});
