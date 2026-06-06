package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.exceptions.NotFoundException;
import id.agenttrust.sdk.models.Delegation;
import id.agenttrust.sdk.models.Session;
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
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DelegationsAPITest {

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
    void testCreate() throws AgentTrustException {
        final String[] receivedFrom = {null};
        handlers.put("/api/v1/delegations", ex -> {
            assertEquals("POST", ex.getRequestMethod());
            String body = readBody(ex);
            Map<String, Object> req = JsonUtil.parse(body);
            receivedFrom[0] = (String) req.get("from_agent_id");
            jsonResponse(ex, 200,
                    "{\"id\":\"d1\",\"from_agent_id\":\"a1\",\"to_agent_id\":\"a2\"," +
                            "\"org_id\":\"org-1\",\"scope\":[\"files:read\"]," +
                            "\"expires_at\":\"2026-12-31T00:00:00Z\"," +
                            "\"created_at\":\"2026-01-01T00:00:00Z\"}");
        });

        try (AgentTrustClient client = startServer()) {
            Delegation d = client.delegations().create(
                    DelegationsAPI.CreateDelegationRequest.builder()
                            .fromAgentId("a1")
                            .toAgentId("a2")
                            .scope(List.of("files:read"))
                            .ttlSeconds(3600)
                            .build()
            );
            assertEquals("d1", d.getId());
            assertEquals("a1", d.getFromAgentId());
            assertEquals(1, d.getScope().size());
            assertEquals("a1", receivedFrom[0]);
        }
    }

    @Test
    void testGet() throws AgentTrustException {
        handlers.put("/api/v1/delegations/d1", ex -> {
            assertEquals("GET", ex.getRequestMethod());
            jsonResponse(ex, 200,
                    "{\"id\":\"d1\",\"from_agent_id\":\"a1\",\"to_agent_id\":\"a2\"," +
                            "\"scope\":[\"files:read\"]}");
        });
        try (AgentTrustClient client = startServer()) {
            Delegation d = client.delegations().get("d1");
            assertEquals("d1", d.getId());
        }
    }

    @Test
    void testList() throws AgentTrustException {
        handlers.put("/api/v1/delegations", ex -> {
            assertEquals("GET", ex.getRequestMethod());
            jsonResponse(ex, 200,
                    "{\"delegations\":[" +
                            "{\"id\":\"d1\",\"from_agent_id\":\"a1\",\"to_agent_id\":\"a2\",\"scope\":[]}," +
                            "{\"id\":\"d2\",\"from_agent_id\":\"a3\",\"to_agent_id\":\"a4\",\"scope\":[]}" +
                            "]}");
        });
        try (AgentTrustClient client = startServer()) {
            List<Delegation> delegations = client.delegations().list();
            assertEquals(2, delegations.size());
            assertEquals("d2", delegations.get(1).getId());
        }
    }

    @Test
    void testRevoke() throws AgentTrustException {
        final boolean[] called = {false};
        handlers.put("/api/v1/delegations/d1", ex -> {
            assertEquals("DELETE", ex.getRequestMethod());
            called[0] = true;
            jsonResponse(ex, 200, "{}");
        });
        try (AgentTrustClient client = startServer()) {
            client.delegations().revoke("d1");
            assertTrue(called[0]);
        }
    }

    @Test
    void testInitSession() throws AgentTrustException {
        handlers.put("/api/v1/delegations/d1/session", ex -> {
            assertEquals("POST", ex.getRequestMethod());
            jsonResponse(ex, 200,
                    "{\"session_id\":\"sess-1\",\"agent_id\":\"a2\",\"org_id\":\"org-1\"," +
                            "\"source\":\"delegation\",\"server_id\":\"\",\"mode\":\"read_only\"," +
                            "\"allowed_actions\":[],\"scope_ceiling\":[\"files:read\"]," +
                            "\"total_calls\":0,\"read_calls\":0,\"write_calls\":0,\"denied_calls\":0," +
                            "\"created_at\":\"2026-01-01T00:00:00Z\"," +
                            "\"last_activity_at\":\"2026-01-01T00:00:00Z\"}");
        });
        try (AgentTrustClient client = startServer()) {
            Session sess = client.delegations().initSession("d1");
            assertEquals("sess-1", sess.getSessionId());
            assertEquals("delegation", sess.getSource());
        }
    }

    @Test
    void testGetNotFound() {
        handlers.put("/api/v1/delegations/missing", ex ->
                jsonResponse(ex, 404, "{\"message\":\"not found\"}")
        );
        try (AgentTrustClient client = startServer()) {
            assertThrows(NotFoundException.class, () -> client.delegations().get("missing"));
        }
    }
}
