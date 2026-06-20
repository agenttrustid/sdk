package id.agenttrust.sdk;

import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Client-side agent identity keys.
 *
 * <p>Agents generate their own Ed25519 keypair and register only the public key
 * with the platform; the private key never leaves the agent. PEM encoding matches
 * the platform parser: X.509 SubjectPublicKeyInfo ("PUBLIC KEY") for the public
 * half and PKCS#8 ("PRIVATE KEY") for the private half. Requires Java 15+.
 */
public final class AgentKeys {

    private AgentKeys() {
    }

    /** A PEM-encoded Ed25519 identity keypair. Only {@link #publicKeyPem()} is sent. */
    public static final class AgentKeyPair {
        private final String publicKeyPem;
        private final String privateKeyPem;

        AgentKeyPair(String publicKeyPem, String privateKeyPem) {
            this.publicKeyPem = publicKeyPem;
            this.privateKeyPem = privateKeyPem;
        }

        public String publicKeyPem() {
            return publicKeyPem;
        }

        public String privateKeyPem() {
            return privateKeyPem;
        }
    }

    /** Generate a new Ed25519 identity keypair for an agent. */
    public static AgentKeyPair generateAgentKey() {
        try {
            KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            return new AgentKeyPair(
                    toPem("PUBLIC KEY", kp.getPublic().getEncoded()),
                    toPem("PRIVATE KEY", kp.getPrivate().getEncoded()));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 is unavailable (requires Java 15+)", e);
        }
    }

    /** Sign {@code data} with a PKCS#8 PEM-encoded Ed25519 private key. */
    public static byte[] signWithPrivateKeyPem(String privateKeyPem, byte[] data) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(parsePrivateKey(privateKeyPem));
            signature.update(data);
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("failed to sign: " + e.getMessage(), e);
        }
    }

    static PrivateKey parsePrivateKey(String privateKeyPem) throws GeneralSecurityException {
        return KeyFactory.getInstance("Ed25519")
                .generatePrivate(new PKCS8EncodedKeySpec(pemBody(privateKeyPem)));
    }

    static PublicKey parsePublicKey(String publicKeyPem) throws GeneralSecurityException {
        return KeyFactory.getInstance("Ed25519")
                .generatePublic(new X509EncodedKeySpec(pemBody(publicKeyPem)));
    }

    private static String toPem(String type, byte[] der) {
        String body = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n";
    }

    private static byte[] pemBody(String pem) {
        if (pem == null) {
            throw new IllegalArgumentException("missing PEM");
        }
        String body = pem.replaceAll("-----BEGIN [^-]+-----", "")
                .replaceAll("-----END [^-]+-----", "")
                .replaceAll("\\s", "");
        if (body.isEmpty()) {
            throw new IllegalArgumentException("invalid PEM: no body");
        }
        return Base64.getDecoder().decode(body);
    }

    /**
     * Persists an agent's private key and signs with it. Native backends can keep
     * the key in the OS secret store; callers sign through the store.
     */
    public interface KeyStore {
        void store(String agentId, String privateKeyPem);

        byte[] sign(String agentId, byte[] data);

        void delete(String agentId);
    }

    /** In-memory key store for tests and ephemeral agents. */
    public static final class InMemoryKeyStore implements KeyStore {
        private final Map<String, String> keys = new HashMap<>();

        @Override
        public void store(String agentId, String privateKeyPem) {
            try {
                parsePrivateKey(privateKeyPem); // validate before storing
            } catch (GeneralSecurityException e) {
                throw new IllegalArgumentException("invalid private key", e);
            }
            keys.put(agentId, privateKeyPem);
        }

        @Override
        public byte[] sign(String agentId, byte[] data) {
            String pem = keys.get(agentId);
            if (pem == null) {
                throw new IllegalStateException("no key stored for agent " + agentId);
            }
            return signWithPrivateKeyPem(pem, data);
        }

        @Override
        public void delete(String agentId) {
            keys.remove(agentId);
        }
    }

    /**
     * Stores agent private keys in the OS secret store via the optional
     * {@code com.github.javakeyring:java-keyring} dependency (macOS Keychain,
     * Windows Credential Manager, Linux Secret Service). The SDK does not depend
     * on it directly — add it to your classpath to use this backend. The backend
     * is injectable for testing.
     */
    public static final class KeychainKeyStore implements KeyStore {

        /** Pluggable OS-secret-store backend. */
        public interface Backend {
            void set(String service, String account, String password);

            String get(String service, String account);

            void delete(String service, String account);
        }

        private static final String SERVICE = "agenttrust-id";

        private final Backend backend;
        private final String service;

        public KeychainKeyStore() {
            this(defaultBackend(), SERVICE);
        }

        KeychainKeyStore(Backend backend, String service) {
            this.backend = backend;
            this.service = service;
        }

        @Override
        public void store(String agentId, String privateKeyPem) {
            try {
                parsePrivateKey(privateKeyPem); // validate before storing
            } catch (GeneralSecurityException e) {
                throw new IllegalArgumentException("invalid private key", e);
            }
            backend.set(service, agentId, privateKeyPem);
        }

        @Override
        public byte[] sign(String agentId, byte[] data) {
            String pem = backend.get(service, agentId);
            if (pem == null) {
                throw new IllegalStateException("no key stored for agent " + agentId);
            }
            return signWithPrivateKeyPem(pem, data);
        }

        @Override
        public void delete(String agentId) {
            backend.delete(service, agentId);
        }

        private static Backend defaultBackend() {
            final Object keyring;
            final Method setM;
            final Method getM;
            final Method delM;
            try {
                Class<?> krClass = Class.forName("com.github.javakeyring.Keyring");
                keyring = krClass.getMethod("create").invoke(null);
                setM = krClass.getMethod("setPassword", String.class, String.class, String.class);
                getM = krClass.getMethod("getPassword", String.class, String.class);
                delM = krClass.getMethod("deletePassword", String.class, String.class);
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException(
                        "KeychainKeyStore requires the optional 'com.github.javakeyring:java-keyring' dependency on the classpath");
            } catch (ReflectiveOperationException e) {
                throw new IllegalStateException("failed to initialize the OS keychain: " + e.getMessage(), e);
            }
            return new Backend() {
                @Override
                public void set(String s, String a, String p) {
                    invoke(setM, keyring, s, a, p);
                }

                @Override
                public String get(String s, String a) {
                    return (String) invoke(getM, keyring, s, a);
                }

                @Override
                public void delete(String s, String a) {
                    invoke(delM, keyring, s, a);
                }
            };
        }

        private static Object invoke(Method method, Object target, Object... args) {
            try {
                return method.invoke(target, args);
            } catch (ReflectiveOperationException e) {
                Throwable cause = e.getCause() != null ? e.getCause() : e;
                throw new RuntimeException(cause.getMessage(), cause);
            }
        }
    }
}
