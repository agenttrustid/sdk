package id.agenttrust.sdk;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DPoPTest {

    private static final String CHECK_URL = "https://api.agenttrust.id/api/v1/agenttrust/check";

    private static Map<String, Object> segObject(String proof, int index) {
        String seg = proof.split("\\.")[index];
        return JsonUtil.parse(new String(Base64.getUrlDecoder().decode(seg), StandardCharsets.UTF_8));
    }

    private static boolean verify(String proof, String publicKeyPem) throws Exception {
        String[] segs = proof.split("\\.");
        byte[] sig = Base64.getUrlDecoder().decode(segs[2]);
        Signature v = Signature.getInstance("Ed25519");
        v.initVerify(AgentKeys.parsePublicKey(publicKeyPem));
        v.update((segs[0] + "." + segs[1]).getBytes(StandardCharsets.UTF_8));
        return v.verify(sig);
    }

    @Test
    void mintsVerifiableProofWithExpectedClaims() throws Exception {
        AgentKeys.AgentKeyPair kp = AgentKeys.generateAgentKey();
        String proof = DPoP.mintDpopProof(kp.privateKeyPem(), kp.publicKeyPem(), "POST", CHECK_URL, "access-tok");

        Map<String, Object> header = segObject(proof, 0);
        Map<String, Object> payload = segObject(proof, 1);

        assertEquals("dpop+jwt", header.get("typ"));
        assertEquals("EdDSA", header.get("alg"));
        @SuppressWarnings("unchecked")
        Map<String, Object> jwk = (Map<String, Object>) header.get("jwk");
        assertEquals("OKP", jwk.get("kty"));
        assertEquals("Ed25519", jwk.get("crv"));
        assertNotNull(jwk.get("x"));

        assertEquals("POST", payload.get("htm"));
        assertEquals(CHECK_URL, payload.get("htu"));
        assertNotNull(payload.get("iat"));
        assertNotNull(payload.get("jti"));

        byte[] sum = MessageDigest.getInstance("SHA-256").digest("access-tok".getBytes(StandardCharsets.UTF_8));
        assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(sum), payload.get("ath"));

        // jwk.x must be the raw 32-byte Ed25519 public key.
        byte[] enc = AgentKeys.parsePublicKey(kp.publicKeyPem()).getEncoded();
        String rawX = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(Arrays.copyOfRange(enc, enc.length - 32, enc.length));
        assertEquals(rawX, jwk.get("x"));

        assertTrue(verify(proof, kp.publicKeyPem()));
    }

    @Test
    void omitsAthWithoutAccessToken() {
        AgentKeys.AgentKeyPair kp = AgentKeys.generateAgentKey();
        Map<String, Object> payload = segObject(
                DPoP.mintDpopProof(kp.privateKeyPem(), kp.publicKeyPem(), "GET", "https://x/y", ""), 1);
        assertFalse(payload.containsKey("ath"));
    }

    @Test
    void mintsUniqueJtiPerCall() {
        AgentKeys.AgentKeyPair kp = AgentKeys.generateAgentKey();
        Object a = segObject(DPoP.mintDpopProof(kp.privateKeyPem(), kp.publicKeyPem(), "POST", CHECK_URL, "t"), 1).get("jti");
        Object b = segObject(DPoP.mintDpopProof(kp.privateKeyPem(), kp.publicKeyPem(), "POST", CHECK_URL, "t"), 1).get("jti");
        assertNotEquals(a, b);
    }

    @Test
    void keyStoreVariantVerifies() throws Exception {
        AgentKeys.AgentKeyPair kp = AgentKeys.generateAgentKey();
        AgentKeys.InMemoryKeyStore ks = new AgentKeys.InMemoryKeyStore();
        ks.store("agent-1", kp.privateKeyPem());
        String proof = DPoP.mintDpopProofWithKeyStore(ks, "agent-1", kp.publicKeyPem(), "POST", CHECK_URL, "tok");
        assertTrue(verify(proof, kp.publicKeyPem()));
    }

    @Test
    void rejectsInvalidPublicKey() {
        AgentKeys.AgentKeyPair kp = AgentKeys.generateAgentKey();
        assertThrows(IllegalArgumentException.class,
                () -> DPoP.mintDpopProof(kp.privateKeyPem(), "not-a-pem", "POST", CHECK_URL, ""));
    }
}
