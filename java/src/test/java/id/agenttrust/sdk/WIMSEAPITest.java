package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.exceptions.AuthenticationException;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class WIMSEAPITest {

    private HttpServer server;
    private String baseUrl;
    private final Map<String, HttpHandler> handlers = new LinkedHashMap<>();

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        baseUrl = "http://localhost:" + server.getAddress().getPort();
    }

    @AfterEach
    void tearDown() {
        if (server != null) server.stop(0);
    }

    private AgentTrustClient startServer() {
        for (Map.Entry<String, HttpHandler> e : handlers.entrySet()) {
            server.createContext(e.getKey(), e.getValue());
        }
        server.start();
        return AgentTrustClient.builder().baseUrl(baseUrl).build();
    }

    private static void jsonResponse(HttpExchange ex, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String readBody(HttpExchange ex) throws IOException {
        try (InputStream is = ex.getRequestBody()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    void testIssueToken() throws AgentTrustException {
        final String[] receivedAgent = {null};
        handlers.put("/api/v1/wimse/token", ex -> {
            assertEquals("POST", ex.getRequestMethod());
            String body = readBody(ex);
            Map<String, Object> req = JsonUtil.parse(body);
            receivedAgent[0] = (String) req.get("agent_id");
            jsonResponse(ex, 200,
                    "{\"token\":\"eyJ.wimse-token\"," +
                            "\"workload_id\":\"spiffe://acme/agent/a1\"," +
                            "\"trust_domain\":\"acme.com\"," +
                            "\"expires_at\":\"2026-12-31T00:00:00Z\"}");
        });
        try (AgentTrustClient client = startServer()) {
            WIMSEAPI.WIMSETokenResponse resp = client.wimse().issueToken(
                    WIMSEAPI.IssueWIMSETokenRequest.builder()
                            .agentId("a1")
                            .serviceName("payments")
                            .environment("prod")
                            .ttlSeconds(3600)
                            .build()
            );
            assertEquals("eyJ.wimse-token", resp.getToken());
            assertEquals("spiffe://acme/agent/a1", resp.getWorkloadId());
            assertEquals("acme.com", resp.getTrustDomain());
            assertEquals("a1", receivedAgent[0]);
        }
    }

    @Test
    void testIssueTokenWithProof() throws Exception {
        AgentKeys.AgentKeyPair kp = AgentKeys.generateAgentKey();
        AgentKeys.InMemoryKeyStore ks = new AgentKeys.InMemoryKeyStore();
        ks.store("a1", kp.privateKeyPem());

        final String nonce = "server-nonce-xyz";
        final Map<String, Object>[] received = new Map[]{null};

        handlers.put("/api/v1/agents/a1/challenge", ex ->
                jsonResponse(ex, 200,
                        "{\"nonce\":\"" + nonce + "\",\"expires_at\":\"2026-12-31T00:00:00Z\"}"));
        handlers.put("/api/v1/wimse/token", ex -> {
            received[0] = JsonUtil.parse(readBody(ex));
            jsonResponse(ex, 200,
                    "{\"token\":\"eyJ.bound\",\"trust_domain\":\"acme.com\"}");
        });

        try (AgentTrustClient client = startServer()) {
            WIMSEAPI.WIMSETokenResponse resp = client.wimse().issueTokenWithProof(
                    WIMSEAPI.IssueWIMSETokenRequest.builder()
                            .agentId("a1")
                            .audience(java.util.List.of("https://api.example.com"))
                            .build(),
                    ks);
            assertEquals("eyJ.bound", resp.getToken());
        }

        assertNotNull(received[0], "server did not receive a request");
        @SuppressWarnings("unchecked")
        Map<String, Object> proof = (Map<String, Object>) received[0].get("proof");
        assertNotNull(proof, "request carried no proof");
        assertEquals(nonce, proof.get("nonce"));

        long ts = ((Number) proof.get("ts")).longValue();
        String message = "pop-v1:" + nonce + ":a1:https://api.example.com:" + ts;
        byte[] sig = java.util.Base64.getUrlDecoder().decode((String) proof.get("signature"));

        java.security.Signature verifier = java.security.Signature.getInstance("Ed25519");
        verifier.initVerify(AgentKeys.parsePublicKey(kp.publicKeyPem()));
        verifier.update(message.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertTrue(verifier.verify(sig), "proof signature must verify against canonical message");
    }

    @Test
    void testVerifyTokenValid() throws AgentTrustException {
        handlers.put("/api/v1/wimse/verify", ex ->
                jsonResponse(ex, 200,
                        "{\"valid\":true,\"agent_id\":\"a1\"," +
                                "\"workload_id\":\"spiffe://acme/agent/a1\"," +
                                "\"trust_domain\":\"acme.com\"," +
                                "\"capabilities\":[\"db:read\",\"db:write\"]}")
        );
        try (AgentTrustClient client = startServer()) {
            WIMSEAPI.VerifyWIMSETokenResponse resp = client.wimse().verifyToken(
                    "eyJ.wimse-token");
            assertTrue(resp.isValid());
            assertEquals("a1", resp.getAgentId());
            assertEquals(2, resp.getCapabilities().size());
        }
    }

    @Test
    void testVerifyTokenInvalid() throws AgentTrustException {
        handlers.put("/api/v1/wimse/verify", ex ->
                jsonResponse(ex, 200,
                        "{\"valid\":false,\"reason\":\"signature mismatch\"}")
        );
        try (AgentTrustClient client = startServer()) {
            WIMSEAPI.VerifyWIMSETokenResponse resp = client.wimse().verifyToken(
                    "tampered.token", "acme.com");
            assertFalse(resp.isValid());
            assertEquals("signature mismatch", resp.getReason());
        }
    }

    @Test
    void testIssueTokenAuthError() {
        handlers.put("/api/v1/wimse/token", ex ->
                jsonResponse(ex, 401, "{\"message\":\"missing api key\"}")
        );
        try (AgentTrustClient client = startServer()) {
            assertThrows(AuthenticationException.class,
                    () -> client.wimse().issueToken(
                            WIMSEAPI.IssueWIMSETokenRequest.builder()
                                    .agentId("a1").build()));
        }
    }
}
