package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.exceptions.AuthenticationException;
import id.agenttrust.sdk.models.FederationProvider;
import id.agenttrust.sdk.models.Session;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class FederationAPITest {

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

    @Test
    void testRegisterProvider() throws AgentTrustException {
        handlers.put("/api/v1/federation/providers", ex -> {
            assertEquals("POST", ex.getRequestMethod());
            jsonResponse(ex, 200,
                    "{\"id\":\"p1\",\"issuer\":\"https://idp.example.com\"," +
                            "\"name\":\"ACME IdP\"," +
                            "\"trust_level\":\"high\",\"status\":\"active\"," +
                            "\"jwks_uri\":\"https://idp.example.com/.well-known/jwks.json\"}");
        });
        try (AgentTrustClient client = startServer()) {
            FederationProvider p = client.federation().registerProvider(
                    "https://idp.example.com", "ACME IdP", "high");
            assertEquals("p1", p.getId());
            assertEquals("ACME IdP", p.getName());
            assertEquals("high", p.getTrustLevel());
        }
    }

    @Test
    void testListProviders() throws AgentTrustException {
        handlers.put("/api/v1/federation/providers", ex ->
                jsonResponse(ex, 200,
                        "{\"providers\":[" +
                                "{\"id\":\"p1\",\"issuer\":\"i1\",\"name\":\"n1\"}," +
                                "{\"id\":\"p2\",\"issuer\":\"i2\",\"name\":\"n2\"}]}")
        );
        try (AgentTrustClient client = startServer()) {
            List<FederationProvider> list = client.federation().listProviders();
            assertEquals(2, list.size());
            assertEquals("p1", list.get(0).getId());
        }
    }

    @Test
    void testDeleteProvider() throws AgentTrustException {
        final boolean[] called = {false};
        handlers.put("/api/v1/federation/providers/p1", ex -> {
            assertEquals("DELETE", ex.getRequestMethod());
            called[0] = true;
            jsonResponse(ex, 200, "{}");
        });
        try (AgentTrustClient client = startServer()) {
            client.federation().deleteProvider("p1");
            assertTrue(called[0]);
        }
    }

    @Test
    void testVerifyToken() throws AgentTrustException {
        handlers.put("/api/v1/federation/tokens/verify", ex ->
                jsonResponse(ex, 200,
                        "{\"valid\":true,\"agent_id\":\"a1\"," +
                                "\"issuer\":\"https://idp.example.com\"," +
                                "\"expires_at\":\"2026-12-31T00:00:00Z\"}")
        );
        try (AgentTrustClient client = startServer()) {
            FederationAPI.VerifyTokenResult r = client.federation().verifyToken(
                    "eyJ.token", "https://idp.example.com");
            assertTrue(r.isValid());
            assertEquals("a1", r.getAgentId());
        }
    }

    @Test
    void testInitSession() throws AgentTrustException {
        handlers.put("/api/v1/federation/sessions/init", ex ->
                jsonResponse(ex, 200,
                        "{\"session_id\":\"s1\",\"agent_id\":\"a1\",\"org_id\":\"org-1\"," +
                                "\"source\":\"federation\",\"mode\":\"read_only\"," +
                                "\"allowed_actions\":[],\"scope_ceiling\":[]," +
                                "\"total_calls\":0,\"read_calls\":0,\"write_calls\":0," +
                                "\"denied_calls\":0," +
                                "\"created_at\":\"2026-01-01T00:00:00Z\"," +
                                "\"last_activity_at\":\"2026-01-01T00:00:00Z\"}")
        );
        try (AgentTrustClient client = startServer()) {
            Session s = client.federation().initSession("eyJ.token", null);
            assertEquals("s1", s.getSessionId());
            assertEquals("federation", s.getSource());
        }
    }

    @Test
    void testIssueIDToken() throws AgentTrustException {
        handlers.put("/api/v1/federation/tokens/issue", ex ->
                jsonResponse(ex, 200,
                        "{\"id_token\":\"eyJ.idtoken\",\"expires_in\":3600}")
        );
        try (AgentTrustClient client = startServer()) {
            FederationAPI.IssueIDTokenResult r = client.federation().issueIDToken(
                    "a1", "https://api.acme.com", "nonce123", 3600);
            assertEquals("eyJ.idtoken", r.getIdToken());
            assertEquals(3600, r.getExpiresIn());
        }
    }

    @Test
    void testVerifyTokenAuthError() {
        handlers.put("/api/v1/federation/tokens/verify", ex ->
                jsonResponse(ex, 401, "{\"message\":\"missing api key\"}")
        );
        try (AgentTrustClient client = startServer()) {
            assertThrows(AuthenticationException.class,
                    () -> client.federation().verifyToken("bogus", null));
        }
    }
}
