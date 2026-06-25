package id.agenttrust.sdk;

import org.junit.jupiter.api.Test;

import java.security.Signature;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AgentKeysTest {

    private static boolean verify(String publicKeyPem, byte[] data, byte[] sig) throws Exception {
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(AgentKeys.parsePublicKey(publicKeyPem));
        verifier.update(data);
        return verifier.verify(sig);
    }

    @Test
    void generatesServerCompatiblePem() throws Exception {
        AgentKeys.AgentKeyPair kp = AgentKeys.generateAgentKey();
        // The platform expects PKIX "PUBLIC KEY" and PKCS#8 "PRIVATE KEY" PEM.
        assertTrue(kp.publicKeyPem().contains("-----BEGIN PUBLIC KEY-----"));
        assertTrue(kp.privateKeyPem().contains("-----BEGIN PRIVATE KEY-----"));
        assertNotNull(AgentKeys.parsePublicKey(kp.publicKeyPem()));
    }

    @Test
    void signVerifiesAgainstPublicKey() throws Exception {
        AgentKeys.AgentKeyPair kp = AgentKeys.generateAgentKey();
        byte[] msg = "proof-of-possession challenge".getBytes();
        byte[] sig = AgentKeys.signWithPrivateKeyPem(kp.privateKeyPem(), msg);
        assertTrue(verify(kp.publicKeyPem(), msg, sig));
    }

    @Test
    void signRejectsInvalidKey() {
        assertThrows(RuntimeException.class,
                () -> AgentKeys.signWithPrivateKeyPem("not-a-pem", "x".getBytes()));
    }

    @Test
    void inMemoryKeyStoreStoreSignDelete() throws Exception {
        AgentKeys.AgentKeyPair kp = AgentKeys.generateAgentKey();
        AgentKeys.InMemoryKeyStore ks = new AgentKeys.InMemoryKeyStore();
        ks.store("agt-1", kp.privateKeyPem());

        byte[] sig = ks.sign("agt-1", "hello".getBytes());
        assertTrue(verify(kp.publicKeyPem(), "hello".getBytes(), sig));
        // signing through the store matches signing the PEM directly
        assertArrayEquals(AgentKeys.signWithPrivateKeyPem(kp.privateKeyPem(), "hello".getBytes()), sig);

        ks.delete("agt-1");
        assertThrows(IllegalStateException.class, () -> ks.sign("agt-1", "hello".getBytes()));
    }

    @Test
    void inMemoryKeyStoreRejectsInvalidKey() {
        AgentKeys.InMemoryKeyStore ks = new AgentKeys.InMemoryKeyStore();
        assertThrows(IllegalArgumentException.class, () -> ks.store("agt", "not-a-pem"));
    }

    @Test
    void keychainKeyStoreUsesInjectedBackend() throws Exception {
        Map<String, String> fake = new HashMap<>();
        AgentKeys.KeychainKeyStore.Backend backend = new AgentKeys.KeychainKeyStore.Backend() {
            @Override
            public void set(String s, String a, String p) {
                fake.put(s + ":" + a, p);
            }

            @Override
            public String get(String s, String a) {
                return fake.get(s + ":" + a);
            }

            @Override
            public void delete(String s, String a) {
                fake.remove(s + ":" + a);
            }
        };
        AgentKeys.KeychainKeyStore ks = new AgentKeys.KeychainKeyStore(backend, "agenttrust-id");
        AgentKeys.AgentKeyPair kp = AgentKeys.generateAgentKey();

        ks.store("agt-1", kp.privateKeyPem());
        assertTrue(fake.containsKey("agenttrust-id:agt-1"));
        byte[] sig = ks.sign("agt-1", "hello".getBytes());
        assertTrue(verify(kp.publicKeyPem(), "hello".getBytes(), sig));

        ks.delete("agt-1");
        assertThrows(IllegalStateException.class, () -> ks.sign("agt-1", "hello".getBytes()));
    }
}
