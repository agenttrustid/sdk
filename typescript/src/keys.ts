/**
 * Client-side agent identity keys.
 *
 * Agents generate their own Ed25519 keypair and register only the public key
 * with the platform; the private key never leaves the agent. PEM encoding
 * matches the platform parser: PKIX SubjectPublicKeyInfo ("PUBLIC KEY") for the
 * public half and PKCS#8 ("PRIVATE KEY") for the private half.
 */
import { generateKeyPairSync, createPrivateKey, sign as edSign } from 'crypto';

export interface AgentKeyPair {
  publicKeyPem: string;
  privateKeyPem: string;
}

/**
 * Generate a new Ed25519 identity keypair for an agent. Register `publicKeyPem`
 * with the platform and keep `privateKeyPem` on the agent (ideally in a KeyStore).
 */
export function generateAgentKey(): AgentKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { publicKeyPem: publicKey as string, privateKeyPem: privateKey as string };
}

/** Sign `data` with a PKCS#8 PEM-encoded Ed25519 private key. */
export function signWithPrivateKeyPem(privateKeyPem: string, data: Uint8Array): Buffer {
  const key = createPrivateKey(privateKeyPem);
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error('private key is not Ed25519');
  }
  return edSign(null, Buffer.from(data), key);
}

/**
 * Persists an agent's private key and signs with it. Native backends can keep
 * the key in the OS secret store; callers sign through the store.
 */
export interface KeyStore {
  store(agentId: string, privateKeyPem: string): void;
  sign(agentId: string, data: Uint8Array): Buffer;
  delete(agentId: string): void;
}

/** In-memory key store for tests and ephemeral agents. */
export class MemoryKeyStore implements KeyStore {
  private readonly keys = new Map<string, string>();

  store(agentId: string, privateKeyPem: string): void {
    createPrivateKey(privateKeyPem); // validate before storing
    this.keys.set(agentId, privateKeyPem);
  }

  sign(agentId: string, data: Uint8Array): Buffer {
    const pem = this.keys.get(agentId);
    if (!pem) {
      throw new Error(`no key stored for agent ${agentId}`);
    }
    return signWithPrivateKeyPem(pem, data);
  }

  delete(agentId: string): void {
    this.keys.delete(agentId);
  }
}

const KEYCHAIN_SERVICE = 'agenttrust-id';

interface KeyringEntry {
  setPassword(password: string): void;
  getPassword(): string;
  deletePassword(): boolean;
}

/**
 * Stores agent private keys in the OS secret store (macOS Keychain, Windows
 * Credential Manager, Linux Secret Service) via the optional `@napi-rs/keyring`
 * package. The SDK does not depend on it directly to stay dependency-free;
 * install it to use this backend: `npm install @napi-rs/keyring`.
 */
export class KeychainKeyStore implements KeyStore {
  constructor(private readonly service: string = KEYCHAIN_SERVICE) {}

  private entry(agentId: string): KeyringEntry {
    let mod: { Entry: new (service: string, account: string) => KeyringEntry };
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      mod = require('@napi-rs/keyring');
    } catch {
      throw new Error(
        "KeychainKeyStore requires the optional '@napi-rs/keyring' package. " +
          'Install it with: npm install @napi-rs/keyring',
      );
    }
    return new mod.Entry(this.service, agentId);
  }

  store(agentId: string, privateKeyPem: string): void {
    createPrivateKey(privateKeyPem); // validate before storing
    this.entry(agentId).setPassword(privateKeyPem);
  }

  sign(agentId: string, data: Uint8Array): Buffer {
    const pem = this.entry(agentId).getPassword();
    return signWithPrivateKeyPem(pem, data);
  }

  delete(agentId: string): void {
    this.entry(agentId).deletePassword();
  }
}
