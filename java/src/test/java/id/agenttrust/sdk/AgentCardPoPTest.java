package id.agenttrust.sdk;

import id.agenttrust.sdk.models.AgentCard;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class AgentCardPoPTest {

    /** Derive the base64url JWK `x` (raw 32-byte key) from a PKIX public PEM. */
    private static String xFromPem(String pem) {
        String b64 = pem.replaceAll("-----[^-]+-----", "").replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(b64);
        byte[] raw = Arrays.copyOfRange(der, der.length - 32, der.length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    private static AgentCard cardWithKey(Map<String, Object> jwk) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("ati_agent_key", jwk);
        Map<String, Object> ext = new LinkedHashMap<>();
        ext.put("uri", "https://agenttrust.id/ext/trust/v1");
        ext.put("params", params);
        Map<String, Object> caps = new LinkedHashMap<>();
        caps.put("extensions", List.of(ext));
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("name", "a");
        data.put("capabilities", caps);
        return AgentCard.fromJson(data);
    }

    @Test
    void extractsEmbeddedKeyAsOriginalPem() {
        AgentKeys.AgentKeyPair kp = AgentKeys.generateAgentKey();
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "OKP");
        jwk.put("crv", "Ed25519");
        jwk.put("x", xFromPem(kp.publicKeyPem()));
        assertEquals(kp.publicKeyPem().trim(), cardWithKey(jwk).getAgentPublicKeyPem().trim());
    }

    @Test
    void returnsNullWhenNoKey() {
        assertNull(AgentCard.fromJson(Map.of("name", "a")).getAgentPublicKeyPem());
    }

    @Test
    void returnsNullForMalformedKey() {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "OKP");
        jwk.put("crv", "Ed25519");
        jwk.put("x", "not base64!!");
        assertNull(cardWithKey(jwk).getAgentPublicKeyPem());
    }
}
