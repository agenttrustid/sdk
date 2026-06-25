package id.agenttrust.sdk;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

/**
 * RFC 9449 DPoP proof minting.
 *
 * <p>Produces the exact JOSE shape the platform verifies, signed with the
 * agent's Ed25519 key (reusing {@link AgentKeys} and the same base64url
 * encoding as proof-of-possession):
 *
 * <pre>
 * header:  {"typ":"dpop+jwt","alg":"EdDSA","jwk":{"kty":"OKP","crv":"Ed25519","x":...}}
 * payload: {"htm","htu","iat","jti","ath"?}
 * </pre>
 *
 * <p>The platform verifies the signature against the embedded JWK and checks
 * the key's thumbprint against the access token's RFC 7800 {@code cnf.jkt}.
 *
 * <p>Both entry points require the agent's public key PEM: unlike the other
 * SDKs, the Java JCA cannot derive an Ed25519 public key from a PKCS#8 private
 * seed, and {@link AgentKeys.KeyStore} is sign-only by design.
 */
public final class DPoP {

    private DPoP() {
    }

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    // SubjectPublicKeyInfo prefix for an Ed25519 public key (alg id 1.3.101.112);
    // the trailing 32 bytes of getEncoded() are the raw public key.
    private static final int RAW_ED25519_PUBLIC_KEY_LEN = 32;

    /**
     * Mints a DPoP proof signed with the agent's Ed25519 private key (PKCS#8 PEM).
     *
     * @param privateKeyPem the agent's PKCS#8 private key PEM (kept on the agent)
     * @param publicKeyPem  the agent's registered X.509 public key PEM
     * @param method        the HTTP method of the request the proof is bound to
     * @param url           the full request URL (htu)
     * @param accessToken   the WIMSE token the proof is bound to (ath); may be empty
     * @return a compact-serialized DPoP proof JWS
     */
    public static String mintDpopProof(
            String privateKeyPem, String publicKeyPem, String method, String url, String accessToken) {
        Map<String, Object> jwk = jwk(publicKeyPem);
        return build(jwk, data -> AgentKeys.signWithPrivateKeyPem(privateKeyPem, data), method, url, accessToken);
    }

    /**
     * Mints a DPoP proof signing through a {@link AgentKeys.KeyStore}, so the
     * private key stays non-exportable; only the public key PEM is handled in the
     * clear.
     *
     * @param keyStore     the key store holding the agent's private key
     * @param agentId      the agent whose key signs the proof
     * @param publicKeyPem the agent's registered X.509 public key PEM
     * @param method       the HTTP method of the request the proof is bound to
     * @param url          the full request URL (htu)
     * @param accessToken  the WIMSE token the proof is bound to (ath); may be empty
     * @return a compact-serialized DPoP proof JWS
     */
    public static String mintDpopProofWithKeyStore(
            AgentKeys.KeyStore keyStore,
            String agentId,
            String publicKeyPem,
            String method,
            String url,
            String accessToken) {
        Map<String, Object> jwk = jwk(publicKeyPem);
        return build(jwk, data -> keyStore.sign(agentId, data), method, url, accessToken);
    }

    private static Map<String, Object> jwk(String publicKeyPem) {
        try {
            PublicKey pub = AgentKeys.parsePublicKey(publicKeyPem);
            byte[] enc = pub.getEncoded();
            if (enc == null || enc.length < RAW_ED25519_PUBLIC_KEY_LEN) {
                throw new IllegalArgumentException("unexpected Ed25519 public key encoding");
            }
            byte[] raw = Arrays.copyOfRange(enc, enc.length - RAW_ED25519_PUBLIC_KEY_LEN, enc.length);
            Map<String, Object> jwk = new LinkedHashMap<>();
            jwk.put("kty", "OKP");
            jwk.put("crv", "Ed25519");
            jwk.put("x", B64URL.encodeToString(raw));
            return jwk;
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("invalid public key: " + e.getMessage(), e);
        }
    }

    private static String build(
            Map<String, Object> jwk,
            Function<byte[], byte[]> sign,
            String method,
            String url,
            String accessToken) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", "dpop+jwt");
        header.put("alg", "EdDSA");
        header.put("jwk", jwk);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("htm", method);
        payload.put("htu", url);
        payload.put("iat", System.currentTimeMillis() / 1000L);
        payload.put("jti", UUID.randomUUID().toString());
        if (accessToken != null && !accessToken.isEmpty()) {
            payload.put("ath", B64URL.encodeToString(sha256(accessToken)));
        }

        String signingInput =
                B64URL.encodeToString(JsonUtil.serialize(header).getBytes(StandardCharsets.UTF_8))
                        + "."
                        + B64URL.encodeToString(JsonUtil.serialize(payload).getBytes(StandardCharsets.UTF_8));
        byte[] sig = sign.apply(signingInput.getBytes(StandardCharsets.UTF_8));
        return signingInput + "." + B64URL.encodeToString(sig);
    }

    private static byte[] sha256(String s) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
