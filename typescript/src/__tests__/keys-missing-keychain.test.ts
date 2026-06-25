// When the optional native keychain dependency is absent, require() throws and
// KeychainKeyStore must surface a clear install hint.
jest.mock(
  '@napi-rs/keyring',
  () => {
    throw new Error('Cannot find module @napi-rs/keyring');
  },
  { virtual: true },
);

import { KeychainKeyStore, generateAgentKey } from '../keys';

describe('KeychainKeyStore without the native dependency', () => {
  it('throws a helpful install error', () => {
    const ks = new KeychainKeyStore();
    const kp = generateAgentKey();
    expect(() => ks.store('agt-1', kp.privateKeyPem)).toThrow(/@napi-rs\/keyring/);
  });
});
