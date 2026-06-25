package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.models.ActionCheckResult;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AgentCredentialsTest {

    private static final String FAR_FUTURE = "2099-01-01T00:00:00Z";

    private HttpServer server;
    private String baseUrl;
    private final AtomicInteger tokenCalls = new AtomicInteger();
    private volatile String capturedAuth;
    private volatile String capturedDpop;

    private AgentKeys.AgentKeyPair kp;
    private AgentKeys.InMemoryKeyStore ks;

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        baseUrl = "http://localhost:" + server.getAddress().getPort();
        kp = AgentKeys.generateAgentKey();
        ks = new AgentKeys.InMemoryKeyStore();
        ks.store("agent-1", kp.privateKeyPem());

        server.createContext("/api/v1/agents/agent-1/challenge", ex ->
                json(ex, "{\"nonce\":\"server-nonce\",\"expires_at\":\"" + FAR_FUTURE + "\"}"));
        server.createContext("/api/v1/wimse/token", ex -> {
            tokenCalls.incrementAndGet();
            json(ex, "{\"token\":\"wimse-tok\",\"expires_at\":\"" + FAR_FUTURE + "\"}");
        });
        server.createContext("/api/v1/agenttrust/check", ex -> {
            capturedAuth = ex.getRequestHeaders().getFirst("Authorization");
            capturedDpop = ex.getRequestHeaders().getFirst("DPoP");
            json(ex, "{\"allowed\":true,\"guard_tier\":\"fast\"}");
        });
        server.start();
    }

    @AfterEach
    void tearDown() {
        if (server != null) server.stop(0);
    }

    private static void json(HttpExchange ex, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private AgentTrustClient client() {
        return AgentTrustClient.builder().baseUrl(baseUrl).build();
    }

    private boolean verifyDpop(String proof) throws Exception {
        String[] segs = proof.split("\\.");
        byte[] sig = Base64.getUrlDecoder().decode(segs[2]);
        Signature v = Signature.getInstance("Ed25519");
        v.initVerify(AgentKeys.parsePublicKey(kp.publicKeyPem()));
        v.update((segs[0] + "." + segs[1]).getBytes(StandardCharsets.UTF_8));
        return v.verify(sig);
    }

    @Test
    void issuesAndCachesToken() throws AgentTrustException {
        try (AgentTrustClient client = client()) {
            AgentCredentials creds = new AgentCredentials(client, ks, "agent-1", kp.publicKeyPem());
            assertEquals("wimse-tok", creds.token());
            creds.token(); // cached (far-future expiry) — must not re-issue
            assertEquals(1, tokenCalls.get());
        }
    }

    @Test
    void runtimeHeadersCarryBearerAndDpop() throws Exception {
        try (AgentTrustClient client = client()) {
            AgentCredentials creds = new AgentCredentials(client, ks, "agent-1", kp.publicKeyPem());
            Map<String, String> headers = creds.runtimeHeaders("POST", "/api/v1/agenttrust/check");
            assertEquals("Bearer wimse-tok", headers.get("Authorization"));
            assertNotNull(headers.get("DPoP"));
            assertTrue(verifyDpop(headers.get("DPoP")));
        }
    }

    @Test
    void checkAttachesBearerAndDpop() throws Exception {
        try (AgentTrustClient client = client()) {
            AgentCredentials creds = new AgentCredentials(client, ks, "agent-1", kp.publicKeyPem());
            client.useAgentCredentials(creds);

            ActionCheckResult result = client.actions().check(
                    ActionsAPI.ActionCheckRequest.builder()
                            .agentId("agent-1")
                            .toolName("read_file")
                            .build());

            assertTrue(result.isAllowed());
            assertEquals("Bearer wimse-tok", capturedAuth);
            assertNotNull(capturedDpop);
            assertTrue(verifyDpop(capturedDpop));
        }
    }

    @Test
    void invalidateForcesReissue() throws AgentTrustException {
        try (AgentTrustClient client = client()) {
            AgentCredentials creds = new AgentCredentials(client, ks, "agent-1", kp.publicKeyPem());
            creds.token();
            creds.invalidate();
            creds.token();
            assertEquals(2, tokenCalls.get());
        }
    }
}
