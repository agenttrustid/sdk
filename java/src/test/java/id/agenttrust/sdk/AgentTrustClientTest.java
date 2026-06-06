package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.*;
import id.agenttrust.sdk.models.*;
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
import java.time.Duration;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the AgentTrust ID Java SDK.
 * <p>
 * Uses the JDK-built-in {@link HttpServer} to mock API responses, so no
 * external test dependencies are needed beyond JUnit 5.
 */
class AgentTrustClientTest {

    private HttpServer server;
    private String baseUrl;
    private final Map<String, HttpHandler> handlers = new LinkedHashMap<>();

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        int port = server.getAddress().getPort();
        baseUrl = "http://localhost:" + port;
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    /** Registers a handler, starts the server, and returns a client. */
    private AgentTrustClient startServer(String apiKey) {
        for (Map.Entry<String, HttpHandler> entry : handlers.entrySet()) {
            server.createContext(entry.getKey(), entry.getValue());
        }
        server.start();

        AgentTrustClient.Builder builder = AgentTrustClient.builder().baseUrl(baseUrl);
        if (apiKey != null) {
            builder.apiKey(apiKey);
        }
        return builder.build();
    }

    private AgentTrustClient startServer() {
        return startServer(null);
    }

    /** Writes a JSON response. */
    private static void jsonResponse(HttpExchange exchange, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    /** Reads the request body as a string. */
    private static String readBody(HttpExchange exchange) throws IOException {
        try (InputStream is = exchange.getRequestBody()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    // ------------------------------------------------------------------
    // Client creation tests
    // ------------------------------------------------------------------

    @Test
    void testBuilderDefaults() {
        AgentTrustClient client = AgentTrustClient.builder().build();
        assertNotNull(client.agents());
        assertNotNull(client.tokens());
        assertNotNull(client.actions());
        assertNotNull(client.telemetry());
        client.close();
    }

    @Test
    void testBuilderWithCustomTimeout() {
        AgentTrustClient client = AgentTrustClient.builder()
                .baseUrl("http://custom:9090")
                .apiKey("sk_test_123")
                .timeout(Duration.ofSeconds(5))
                .build();
        assertNotNull(client);
        client.close();
    }

    @Test
    void testBuilderWithCustomHttpClient() {
        java.net.http.HttpClient custom = java.net.http.HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(99))
                .build();
        AgentTrustClient client = AgentTrustClient.builder()
                .httpClient(custom)
                .build();
        assertNotNull(client);
        client.close();
    }

    @Test
    void testFromEnvDefaults() {
        // With no env vars set, should use defaults
        AgentTrustClient client = AgentTrustClient.fromEnv();
        assertNotNull(client);
        client.close();
    }

    // ------------------------------------------------------------------
    // Health check
    // ------------------------------------------------------------------

    @Test
    void testHealth() throws AgentTrustException {
        handlers.put("/health", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                jsonResponse(exchange, 200,
                        "{\"status\":\"healthy\",\"service\":\"gateway\",\"version\":\"1.0.0\"}");
            } else {
                jsonResponse(exchange, 405, "{\"message\":\"method not allowed\"}");
            }
        });
        try (AgentTrustClient client = startServer()) {
            HealthResponse health = client.health();
            assertEquals("healthy", health.getStatus());
            assertEquals("gateway", health.getService());
            assertEquals("1.0.0", health.getVersion());
        }
    }

    // ------------------------------------------------------------------
    // Agents API
    // ------------------------------------------------------------------

    @Test
    void testAgentsCreate() throws AgentTrustException {
        handlers.put("/api/v1/agents", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                jsonResponse(exchange, 405, "{\"message\":\"method not allowed\"}");
                return;
            }
            String body = readBody(exchange);
            Map<String, Object> req = JsonUtil.parse(body);

            String resp = "{\"agent\":{" +
                    "\"id\":\"agent-123\"," +
                    "\"name\":\"" + req.get("name") + "\"," +
                    "\"org_id\":\"org-1\"," +
                    "\"framework\":\"" + req.get("framework") + "\"," +
                    "\"public_key\":\"-----BEGIN PUBLIC KEY-----\"," +
                    "\"status\":\"active\"," +
                    "\"capabilities\":[\"web_search\",\"files:read\"]," +
                    "\"metadata\":{}," +
                    "\"created_at\":\"2026-01-01T00:00:00Z\"," +
                    "\"private_key\":\"-----BEGIN PRIVATE KEY-----\"" +
                    "}}";
            jsonResponse(exchange, 200, resp);
        });

        try (AgentTrustClient client = startServer("sk_test")) {
            Agent agent = client.agents().create(
                    CreateAgentRequest.builder()
                            .name("test-agent")
                            .framework("langchain")
                            .capabilities(List.of("web_search", "files:read"))
                            .build()
            );
            assertEquals("agent-123", agent.getId());
            assertEquals("test-agent", agent.getName());
            assertEquals("langchain", agent.getFramework());
            assertEquals("active", agent.getStatus());
            assertEquals(2, agent.getCapabilities().size());
            assertEquals("-----BEGIN PRIVATE KEY-----", agent.getPrivateKey());
        }
    }

    @Test
    void testAgentsCreateValidationError() {
        handlers.put("/api/v1/agents", exchange -> {
            jsonResponse(exchange, 400, "{\"message\":\"name is required\"}");
        });

        try (AgentTrustClient client = startServer()) {
            assertThrows(ValidationException.class, () ->
                    client.agents().create(
                            CreateAgentRequest.builder().name("x").build()
                    ));
        }
    }

    @Test
    void testAgentsGet() throws AgentTrustException {
        handlers.put("/api/v1/agents/agent-123", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                jsonResponse(exchange, 200,
                        "{\"id\":\"agent-123\",\"name\":\"my-agent\",\"org_id\":\"org-1\"," +
                                "\"framework\":\"custom\",\"status\":\"active\"," +
                                "\"capabilities\":[\"read\"],\"created_at\":\"2026-01-01T00:00:00Z\"}");
            }
        });

        try (AgentTrustClient client = startServer()) {
            Agent agent = client.agents().get("agent-123");
            assertEquals("agent-123", agent.getId());
            assertEquals("my-agent", agent.getName());
        }
    }

    @Test
    void testAgentsGetNotFound() {
        handlers.put("/api/v1/agents/nonexistent", exchange ->
                jsonResponse(exchange, 404, "{\"message\":\"agent not found\"}")
        );

        try (AgentTrustClient client = startServer()) {
            assertThrows(NotFoundException.class, () ->
                    client.agents().get("nonexistent"));
        }
    }

    @Test
    void testAgentsList() throws AgentTrustException {
        handlers.put("/api/v1/agents", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                jsonResponse(exchange, 200,
                        "{\"agents\":[" +
                                "{\"id\":\"a1\",\"name\":\"agent-1\",\"status\":\"active\",\"framework\":\"custom\",\"capabilities\":[]}," +
                                "{\"id\":\"a2\",\"name\":\"agent-2\",\"status\":\"revoked\",\"framework\":\"langchain\",\"capabilities\":[\"search\"]}" +
                                "]}");
            }
        });

        try (AgentTrustClient client = startServer()) {
            List<Agent> agents = client.agents().list();
            assertEquals(2, agents.size());
            assertEquals("agent-1", agents.get(0).getName());
            assertEquals("revoked", agents.get(1).getStatus());
        }
    }

    @Test
    void testAgentsRevoke() throws AgentTrustException {
        final String[] receivedReason = {null};

        handlers.put("/api/v1/agents/agent-123/revoke", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                String body = readBody(exchange);
                Map<String, Object> req = JsonUtil.parse(body);
                receivedReason[0] = (String) req.get("reason");
                jsonResponse(exchange, 200, "{\"success\":true}");
            }
        });

        try (AgentTrustClient client = startServer()) {
            client.agents().revoke("agent-123", "compromised");
            assertEquals("compromised", receivedReason[0]);
        }
    }

    // ------------------------------------------------------------------
    // Tokens API
    // ------------------------------------------------------------------

    @Test
    void testTokensIssue() throws AgentTrustException {
        handlers.put("/api/v1/agent-tokens/issue", exchange -> {
            jsonResponse(exchange, 200,
                    "{\"token\":\"at_xK3z9abcdef\"," +
                            "\"agent_id\":\"agent-123\"," +
                            "\"scopes\":[\"files:read\"]," +
                            "\"audience\":[\"mcp://filesystem\"]," +
                            "\"issued_at\":\"2026-01-01T00:00:00Z\"," +
                            "\"expires_at\":\"2026-01-01T00:05:00Z\"," +
                            "\"token_id\":\"tok-456\"}");
        });

        try (AgentTrustClient client = startServer()) {
            Token token = client.tokens().issue(
                    TokensAPI.IssueTokenRequest.builder()
                            .agentId("agent-123")
                            .scope(List.of("files:read"))
                            .audience(List.of("mcp://filesystem"))
                            .ttl(300)
                            .build()
            );
            assertTrue(token.getToken().startsWith("at_"));
            assertEquals("agent-123", token.getAgentId());
            assertEquals(1, token.getScopes().size());
            assertEquals("files:read", token.getScopes().get(0));
            assertEquals("tok-456", token.getTokenId());
        }
    }

    @Test
    void testTokensIntrospect() throws AgentTrustException {
        handlers.put("/api/v1/agent-tokens/introspect", exchange -> {
            jsonResponse(exchange, 200,
                    "{\"active\":true,\"agent_id\":\"agent-123\",\"org_id\":\"org-1\"," +
                            "\"scopes\":[\"files:read\"],\"reasoning\":\"capability match\"," +
                            "\"guard_tier\":\"fast\",\"confidence\":0.95,\"latency_ms\":12}");
        });

        try (AgentTrustClient client = startServer()) {
            IntrospectionResult result = client.tokens().introspect(
                    TokensAPI.IntrospectTokenRequest.builder()
                            .token("at_test")
                            .target("mcp://filesystem")
                            .requiredScopes(List.of("files:read"))
                            .build()
            );
            assertTrue(result.isActive());
            assertEquals("agent-123", result.getAgentId());
            assertEquals("org-1", result.getOrgId());
            assertEquals("capability match", result.getReasoning());
            assertEquals("fast", result.getGuardTier());
            assertEquals(0.95, result.getConfidence(), 0.001);
            assertEquals(12, result.getLatencyMs());
        }
    }

    @Test
    void testTokensRevoke() throws AgentTrustException {
        final String[] receivedToken = {null};
        final String[] receivedReason = {null};

        handlers.put("/api/v1/agent-tokens/revoke", exchange -> {
            String body = readBody(exchange);
            Map<String, Object> req = JsonUtil.parse(body);
            receivedToken[0] = (String) req.get("token");
            receivedReason[0] = (String) req.get("reason");
            jsonResponse(exchange, 200, "{\"success\":true}");
        });

        try (AgentTrustClient client = startServer()) {
            client.tokens().revoke("at_revoke_me", "key_compromised");
            assertEquals("at_revoke_me", receivedToken[0]);
            assertEquals("key_compromised", receivedReason[0]);
        }
    }

    // ------------------------------------------------------------------
    // Actions API
    // ------------------------------------------------------------------

    @Test
    void testActionsCheckAllowed() throws AgentTrustException {
        handlers.put("/api/v1/agenttrust/check", exchange -> {
            jsonResponse(exchange, 200,
                    "{\"allowed\":true,\"check_id\":\"chk-1\"," +
                            "\"confidence\":0.95,\"guard_tier\":\"fast\"," +
                            "\"latency_ms\":12,\"reason\":\"capability match\"}");
        });

        try (AgentTrustClient client = startServer()) {
            ActionCheckResult result = client.actions().check(
                    ActionsAPI.ActionCheckRequest.builder()
                            .agentId("agent-1")
                            .toolName("web_search")
                            .toolInputSummary("search query")
                            .build()
            );
            assertTrue(result.isAllowed());
            assertEquals("chk-1", result.getCheckId());
            assertEquals("fast", result.getGuardTier());
        }
    }

    @Test
    void testActionsCheckDenied() throws AgentTrustException {
        handlers.put("/api/v1/agenttrust/check", exchange -> {
            jsonResponse(exchange, 200,
                    "{\"allowed\":false,\"confidence\":0.95," +
                            "\"guard_tier\":\"fast\",\"reason\":\"capability not registered\"}");
        });

        try (AgentTrustClient client = startServer()) {
            ActionCheckResult result = client.actions().check(
                    ActionsAPI.ActionCheckRequest.builder()
                            .agentId("agent-1")
                            .toolName("delete_all")
                            .build()
            );
            assertFalse(result.isAllowed());
            assertEquals("capability not registered", result.getReason());
        }
    }

    @Test
    void testActionsCheckTruncatesInput() throws AgentTrustException {
        final String[] receivedSummary = {null};

        handlers.put("/api/v1/agenttrust/check", exchange -> {
            String body = readBody(exchange);
            Map<String, Object> req = JsonUtil.parse(body);
            receivedSummary[0] = (String) req.get("action_input_summary");
            jsonResponse(exchange, 200, "{\"allowed\":true}");
        });

        try (AgentTrustClient client = startServer()) {
            String longInput = "x".repeat(500);
            client.actions().check(
                    ActionsAPI.ActionCheckRequest.builder()
                            .agentId("agent-1")
                            .toolName("tool_a")
                            .toolInputSummary(longInput)
                            .build()
            );
            assertNotNull(receivedSummary[0]);
            assertTrue(receivedSummary[0].length() <= 200,
                    "Expected input truncated to 200 chars, got " + receivedSummary[0].length());
        }
    }

    // ------------------------------------------------------------------
    // Telemetry API
    // ------------------------------------------------------------------

    @Test
    void testTelemetryReport() throws AgentTrustException {
        final String[] receivedAgentId = {null};
        final int[] receivedEventCount = {0};

        handlers.put("/api/v1/telemetry/report", exchange -> {
            String body = readBody(exchange);
            Map<String, Object> req = JsonUtil.parse(body);
            receivedAgentId[0] = (String) req.get("agent_id");
            @SuppressWarnings("unchecked")
            List<Object> events = (List<Object>) req.get("events");
            receivedEventCount[0] = events != null ? events.size() : 0;
            jsonResponse(exchange, 200,
                    "{\"accepted\":true,\"events_processed\":" + receivedEventCount[0] + "}");
        });

        try (AgentTrustClient client = startServer()) {
            List<TelemetryEvent> events = List.of(
                    new TelemetryEvent("tool_end", "search", 100, true, null, "2026-01-01T00:00:00Z"),
                    new TelemetryEvent("tool_error", "analyze", 50, false, "timeout", "2026-01-01T00:00:01Z")
            );
            client.telemetry().report("agent-1", "sess-1", events);
            assertEquals("agent-1", receivedAgentId[0]);
            assertEquals(2, receivedEventCount[0]);
        }
    }

    // ------------------------------------------------------------------
    // Guard tests
    // ------------------------------------------------------------------

    @Test
    void testGuardCheckAllowed() throws AgentTrustException {
        handlers.put("/api/v1/agenttrust/check", exchange -> {
            jsonResponse(exchange, 200,
                    "{\"allowed\":true,\"check_id\":\"chk-1\",\"confidence\":0.95,\"guard_tier\":\"fast\"}");
        });

        try (AgentTrustClient client = startServer()) {
            AgentTrustGuard guard = new AgentTrustGuard(client, "agent-1");
            // Should not throw
            guard.check("web_search", "query about AI");
        }
    }

    @Test
    void testGuardCheckDeniedBlockOnDeny() {
        handlers.put("/api/v1/agenttrust/check", exchange -> {
            jsonResponse(exchange, 200,
                    "{\"allowed\":false,\"reason\":\"capability not registered\"}");
        });

        try (AgentTrustClient client = startServer()) {
            AgentTrustGuard guard = new AgentTrustGuard(client, "agent-1");
            AgentTrustException ex = assertThrows(AgentTrustException.class, () ->
                    guard.check("drop_database", ""));
            assertTrue(ex.getMessage().contains("denied"));
            assertEquals("ACTION_DENIED", ex.getCode());
        }
    }

    @Test
    void testGuardCheckDeniedNoBlock() throws AgentTrustException {
        handlers.put("/api/v1/agenttrust/check", exchange -> {
            jsonResponse(exchange, 200,
                    "{\"allowed\":false,\"reason\":\"not registered\"}");
        });

        try (AgentTrustClient client = startServer()) {
            AgentTrustGuard.Options opts = new AgentTrustGuard.Options();
            opts.blockOnDeny = false;
            AgentTrustGuard guard = new AgentTrustGuard(client, "agent-1", opts);
            // Should not throw even though denied
            guard.check("dangerous_tool", "");
        }
    }

    @Test
    void testGuardCheckNetworkErrorFailClosed() {
        // Point at a server that doesn't exist
        AgentTrustClient client = AgentTrustClient.builder()
                .baseUrl("http://127.0.0.1:1")
                .timeout(Duration.ofMillis(200))
                .build();
        AgentTrustGuard guard = new AgentTrustGuard(client, "agent-1");

        AgentTrustException ex = assertThrows(AgentTrustException.class, () ->
                guard.check("web_search", ""));
        assertTrue(ex.getMessage().contains("Guardian unreachable"),
                "Expected 'Guardian unreachable' in message, got: " + ex.getMessage());
        client.close();
    }

    @Test
    void testGuardCheckNetworkErrorFailOpen() throws AgentTrustException {
        // Point at a server that doesn't exist
        AgentTrustClient client = AgentTrustClient.builder()
                .baseUrl("http://127.0.0.1:1")
                .timeout(Duration.ofMillis(200))
                .build();
        AgentTrustGuard.Options opts = new AgentTrustGuard.Options();
        opts.failOpen = true;
        AgentTrustGuard guard = new AgentTrustGuard(client, "agent-1", opts);

        // Should not throw with failOpen=true
        guard.check("web_search", "");
        client.close();
    }

    @Test
    void testGuardCustomSessionId() throws AgentTrustException {
        final String[] receivedSessionId = {null};

        handlers.put("/api/v1/agenttrust/check", exchange -> {
            String body = readBody(exchange);
            Map<String, Object> req = JsonUtil.parse(body);
            receivedSessionId[0] = (String) req.get("session_id");
            jsonResponse(exchange, 200, "{\"allowed\":true}");
        });

        try (AgentTrustClient client = startServer()) {
            AgentTrustGuard.Options opts = new AgentTrustGuard.Options();
            opts.sessionId = "my-session-id";
            AgentTrustGuard guard = new AgentTrustGuard(client, "agent-1", opts);
            guard.check("tool_a", "");
            assertEquals("my-session-id", receivedSessionId[0]);
        }
    }

    @Test
    void testGuardReportBuffersEvents() throws AgentTrustException {
        final int[] callCount = {0};

        handlers.put("/api/v1/telemetry/report", exchange -> {
            callCount[0]++;
            jsonResponse(exchange, 200, "{\"accepted\":true}");
        });
        // Also need action check for guard creation context
        handlers.put("/api/v1/agenttrust/check", exchange -> {
            jsonResponse(exchange, 200, "{\"allowed\":true}");
        });

        try (AgentTrustClient client = startServer()) {
            AgentTrustGuard guard = new AgentTrustGuard(client, "agent-1");
            // Report fewer than 10 events -- should not trigger a flush
            guard.report("search", true, 120);
            guard.report("analyze", false, 50);
            assertEquals(0, callCount[0], "Expected no flush yet");
        }
    }

    @Test
    void testGuardReportAutoFlushAt10() throws AgentTrustException {
        final List<String> receivedToolNames = Collections.synchronizedList(new ArrayList<>());

        handlers.put("/api/v1/telemetry/report", exchange -> {
            String body = readBody(exchange);
            Map<String, Object> req = JsonUtil.parse(body);
            @SuppressWarnings("unchecked")
            List<Object> events = (List<Object>) req.get("events");
            if (events != null) {
                for (Object e : events) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> ev = (Map<String, Object>) e;
                    receivedToolNames.add((String) ev.get("tool_name"));
                }
            }
            jsonResponse(exchange, 200, "{\"accepted\":true}");
        });

        try (AgentTrustClient client = startServer()) {
            AgentTrustGuard guard = new AgentTrustGuard(client, "agent-1");
            for (int i = 0; i < 10; i++) {
                guard.report("tool_" + (char) ('a' + i), true, 10);
            }
            // Auto-flush should have been triggered
            assertEquals(10, receivedToolNames.size(),
                    "Expected 10 events after auto-flush, got " + receivedToolNames.size());
        }
    }

    @Test
    void testGuardFlush() throws AgentTrustException {
        final List<String> receivedToolNames = new ArrayList<>();

        handlers.put("/api/v1/telemetry/report", exchange -> {
            String body = readBody(exchange);
            Map<String, Object> req = JsonUtil.parse(body);
            @SuppressWarnings("unchecked")
            List<Object> events = (List<Object>) req.get("events");
            if (events != null) {
                for (Object e : events) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> ev = (Map<String, Object>) e;
                    receivedToolNames.add((String) ev.get("tool_name"));
                }
            }
            jsonResponse(exchange, 200, "{\"accepted\":true}");
        });

        try (AgentTrustClient client = startServer()) {
            AgentTrustGuard guard = new AgentTrustGuard(client, "agent-1");
            guard.report("search", true, 120);
            guard.report("analyze", true, 200);
            guard.flush();
            assertEquals(2, receivedToolNames.size());
            assertEquals("search", receivedToolNames.get(0));
        }
    }

    @Test
    void testGuardClose() throws AgentTrustException {
        final boolean[] flushCalled = {false};

        handlers.put("/api/v1/telemetry/report", exchange -> {
            flushCalled[0] = true;
            jsonResponse(exchange, 200, "{\"accepted\":true}");
        });

        try (AgentTrustClient client = startServer()) {
            AgentTrustGuard guard = new AgentTrustGuard(client, "agent-1");
            guard.report("tool_a", true, 10);
            guard.close();
            assertTrue(flushCalled[0], "Expected Close to flush remaining events");
        }
    }

    // ------------------------------------------------------------------
    // Error handling
    // ------------------------------------------------------------------

    @Test
    void testErrorAuthentication() {
        handlers.put("/health", exchange ->
                jsonResponse(exchange, 401, "{\"message\":\"invalid key\"}")
        );

        try (AgentTrustClient client = startServer()) {
            assertThrows(AuthenticationException.class, () -> client.health());
        }
    }

    @Test
    void testErrorAuthorization() {
        handlers.put("/health", exchange ->
                jsonResponse(exchange, 403, "{\"message\":\"forbidden\"}")
        );

        try (AgentTrustClient client = startServer()) {
            assertThrows(AuthorizationException.class, () -> client.health());
        }
    }

    @Test
    void testErrorServerError() {
        handlers.put("/health", exchange ->
                jsonResponse(exchange, 500, "{\"message\":\"internal error\"}")
        );

        try (AgentTrustClient client = startServer()) {
            AgentTrustException ex = assertThrows(AgentTrustException.class, () -> client.health());
            assertEquals("HTTP_500", ex.getCode());
        }
    }

    @Test
    void testErrorNetworkError() {
        AgentTrustClient client = AgentTrustClient.builder()
                .baseUrl("http://127.0.0.1:1")
                .timeout(Duration.ofMillis(200))
                .build();

        assertThrows(NetworkException.class, () -> client.health());
        client.close();
    }

    @Test
    void testApiKeyHeaderPropagation() throws AgentTrustException {
        final String[] receivedKey = {null};

        handlers.put("/health", exchange -> {
            receivedKey[0] = exchange.getRequestHeaders().getFirst("X-API-Key");
            jsonResponse(exchange, 200, "{\"status\":\"healthy\"}");
        });

        try (AgentTrustClient client = startServer("sk_test_abc")) {
            client.health();
            assertEquals("sk_test_abc", receivedKey[0]);
        }
    }

    // ------------------------------------------------------------------
    // Sessions API
    // ------------------------------------------------------------------

    @Test
    void testSessionsInitSession() throws AgentTrustException {
        handlers.put("/mcp/sessions/init", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                jsonResponse(exchange, 405, "{\"message\":\"method not allowed\"}");
                return;
            }
            String body = readBody(exchange);
            Map<String, Object> req = JsonUtil.parse(body);
            jsonResponse(exchange, 200,
                    "{\"session_id\":\"sess-001\"," +
                            "\"agent_id\":\"" + req.get("agent_id") + "\"," +
                            "\"org_id\":\"org-1\"," +
                            "\"source\":\"mcp\"," +
                            "\"server_id\":\"" + req.get("server_id") + "\"," +
                            "\"mode\":\"normal\"," +
                            "\"allowed_actions\":[\"read\",\"write\"]," +
                            "\"scope_ceiling\":[\"files:read\",\"files:write\"]," +
                            "\"total_calls\":0," +
                            "\"read_calls\":0," +
                            "\"write_calls\":0," +
                            "\"denied_calls\":0," +
                            "\"created_at\":\"2026-01-01T00:00:00Z\"," +
                            "\"last_activity_at\":\"2026-01-01T00:00:00Z\"}");
        });

        try (AgentTrustClient client = startServer("sk_test")) {
            Session session = client.sessions().initSession("agent-123", "server-abc");
            assertEquals("sess-001", session.getSessionId());
            assertEquals("agent-123", session.getAgentId());
            assertEquals("org-1", session.getOrgId());
            assertEquals("mcp", session.getSource());
            assertEquals("server-abc", session.getServerId());
            assertEquals("normal", session.getMode());
            assertEquals(2, session.getAllowedActions().size());
            assertEquals("read", session.getAllowedActions().get(0));
            assertEquals(2, session.getScopeCeiling().size());
            assertEquals(0, session.getTotalCalls());
            assertEquals(0, session.getDeniedCalls());
            assertNotNull(session.getCreatedAt());
        }
    }

    @Test
    void testSessionsGetSession() throws AgentTrustException {
        handlers.put("/mcp/sessions/sess-001", exchange -> {
            if (!"GET".equals(exchange.getRequestMethod())) {
                jsonResponse(exchange, 405, "{\"message\":\"method not allowed\"}");
                return;
            }
            jsonResponse(exchange, 200,
                    "{\"session_id\":\"sess-001\"," +
                            "\"agent_id\":\"agent-123\"," +
                            "\"org_id\":\"org-1\"," +
                            "\"source\":\"mcp\"," +
                            "\"server_id\":\"server-abc\"," +
                            "\"mode\":\"elevated\"," +
                            "\"allowed_actions\":[\"read\"]," +
                            "\"scope_ceiling\":[]," +
                            "\"total_calls\":5," +
                            "\"read_calls\":3," +
                            "\"write_calls\":1," +
                            "\"denied_calls\":1," +
                            "\"created_at\":\"2026-01-01T00:00:00Z\"," +
                            "\"last_activity_at\":\"2026-01-01T00:01:00Z\"}");
        });

        try (AgentTrustClient client = startServer()) {
            Session session = client.sessions().getSession("sess-001");
            assertEquals("sess-001", session.getSessionId());
            assertEquals("elevated", session.getMode());
            assertEquals(5, session.getTotalCalls());
            assertEquals(3, session.getReadCalls());
            assertEquals(1, session.getWriteCalls());
            assertEquals(1, session.getDeniedCalls());
        }
    }

    // ------------------------------------------------------------------
    // Approvals API
    // ------------------------------------------------------------------

    @Test
    void testApprovalsApprove() throws AgentTrustException {
        final String[] receivedDecidedBy = {null};

        handlers.put("/mcp/approvals/apr-001/approve", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                jsonResponse(exchange, 405, "{\"message\":\"method not allowed\"}");
                return;
            }
            String body = readBody(exchange);
            Map<String, Object> req = JsonUtil.parse(body);
            receivedDecidedBy[0] = (String) req.get("decided_by");
            jsonResponse(exchange, 200, "{\"success\":true}");
        });

        try (AgentTrustClient client = startServer()) {
            client.approvals().approve("apr-001", "admin@example.com");
            assertEquals("admin@example.com", receivedDecidedBy[0]);
        }
    }

    @Test
    void testApprovalsDeny() throws AgentTrustException {
        final String[] receivedDecidedBy = {null};

        handlers.put("/mcp/approvals/apr-002/deny", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                jsonResponse(exchange, 405, "{\"message\":\"method not allowed\"}");
                return;
            }
            String body = readBody(exchange);
            Map<String, Object> req = JsonUtil.parse(body);
            receivedDecidedBy[0] = (String) req.get("decided_by");
            jsonResponse(exchange, 200, "{\"success\":true}");
        });

        try (AgentTrustClient client = startServer()) {
            client.approvals().deny("apr-002", "security@example.com");
            assertEquals("security@example.com", receivedDecidedBy[0]);
        }
    }

    @Test
    void testApprovalsGet() throws AgentTrustException {
        handlers.put("/mcp/approvals/apr-001", exchange -> {
            if (!"GET".equals(exchange.getRequestMethod())) {
                jsonResponse(exchange, 405, "{\"message\":\"method not allowed\"}");
                return;
            }
            jsonResponse(exchange, 200,
                    "{\"id\":\"apr-001\"," +
                            "\"session_id\":\"sess-001\"," +
                            "\"agent_id\":\"agent-123\"," +
                            "\"org_id\":\"org-1\"," +
                            "\"action_name\":\"delete_file\"," +
                            "\"action_effect\":\"write\"," +
                            "\"status\":\"pending\"," +
                            "\"created_at\":\"2026-01-01T00:00:00Z\"," +
                            "\"expires_at\":\"2026-01-01T00:05:00Z\"," +
                            "\"decided_by\":null}");
        });

        try (AgentTrustClient client = startServer()) {
            ApprovalRequest approval = client.approvals().get("apr-001");
            assertEquals("apr-001", approval.getId());
            assertEquals("sess-001", approval.getSessionId());
            assertEquals("agent-123", approval.getAgentId());
            assertEquals("delete_file", approval.getActionName());
            assertEquals("write", approval.getActionEffect());
            assertEquals("pending", approval.getStatus());
            assertNotNull(approval.getCreatedAt());
            assertNotNull(approval.getExpiresAt());
            assertNull(approval.getDecidedBy());
        }
    }

    // ------------------------------------------------------------------
    // Actions API - actionEffect and elevation
    // ------------------------------------------------------------------

    @Test
    void testActionsCheckWithActionEffect() throws AgentTrustException {
        final String[] receivedEffect = {null};

        handlers.put("/api/v1/agenttrust/check", exchange -> {
            String body = readBody(exchange);
            Map<String, Object> req = JsonUtil.parse(body);
            receivedEffect[0] = (String) req.get("action_effect");
            jsonResponse(exchange, 200, "{\"allowed\":true,\"check_id\":\"chk-2\"}");
        });

        try (AgentTrustClient client = startServer()) {
            ActionCheckResult result = client.actions().check(
                    ActionsAPI.ActionCheckRequest.builder()
                            .agentId("agent-1")
                            .toolName("write_file")
                            .actionEffect("write")
                            .build()
            );
            assertTrue(result.isAllowed());
            assertEquals("write", receivedEffect[0]);
        }
    }

    @Test
    void testActionsCheckElevationRequired() throws AgentTrustException {
        handlers.put("/api/v1/agenttrust/check", exchange -> {
            jsonResponse(exchange, 200,
                    "{\"allowed\":false," +
                            "\"elevation_required\":true," +
                            "\"approval_id\":\"apr-999\"," +
                            "\"reason\":\"action requires elevation\"}");
        });

        try (AgentTrustClient client = startServer()) {
            ActionCheckResult result = client.actions().check(
                    ActionsAPI.ActionCheckRequest.builder()
                            .agentId("agent-1")
                            .toolName("admin_action")
                            .build()
            );
            assertFalse(result.isAllowed());
            assertTrue(result.isElevationRequired());
            assertEquals("apr-999", result.getApprovalId());
        }
    }

    // ------------------------------------------------------------------
    // Guard - elevation and actionEffect tests
    // ------------------------------------------------------------------

    @Test
    void testGuardCheckThrowsElevationRequired() {
        handlers.put("/api/v1/agenttrust/check", exchange -> {
            jsonResponse(exchange, 200,
                    "{\"allowed\":false," +
                            "\"elevation_required\":true," +
                            "\"approval_id\":\"apr-123\"," +
                            "\"reason\":\"requires approval\"}");
        });

        try (AgentTrustClient client = startServer()) {
            AgentTrustGuard guard = new AgentTrustGuard(client, "agent-1");
            ElevationRequiredException ex = assertThrows(
                    ElevationRequiredException.class,
                    () -> guard.check("admin_tool", "do admin stuff"));
            assertEquals("apr-123", ex.getApprovalId());
            assertEquals("ELEVATION_REQUIRED", ex.getCode());
            assertTrue(ex.getMessage().contains("admin_tool"));
        }
    }

    @Test
    void testGuardCheckWithActionEffect() throws AgentTrustException {
        final String[] receivedEffect = {null};

        handlers.put("/api/v1/agenttrust/check", exchange -> {
            String body = readBody(exchange);
            Map<String, Object> req = JsonUtil.parse(body);
            receivedEffect[0] = (String) req.get("action_effect");
            jsonResponse(exchange, 200, "{\"allowed\":true}");
        });

        try (AgentTrustClient client = startServer()) {
            AgentTrustGuard guard = new AgentTrustGuard(client, "agent-1");
            guard.check("write_file", "write to /tmp/test.txt", "write");
            assertEquals("write", receivedEffect[0]);
        }
    }

    @Test
    void testGuardCheckElevationWithBlockOnDenyFalse() throws AgentTrustException {
        handlers.put("/api/v1/agenttrust/check", exchange -> {
            jsonResponse(exchange, 200,
                    "{\"allowed\":false," +
                            "\"elevation_required\":true," +
                            "\"approval_id\":\"apr-456\"," +
                            "\"reason\":\"requires approval\"}");
        });

        try (AgentTrustClient client = startServer()) {
            AgentTrustGuard.Options opts = new AgentTrustGuard.Options();
            opts.blockOnDeny = false;
            AgentTrustGuard guard = new AgentTrustGuard(client, "agent-1", opts);
            // Should NOT throw because blockOnDeny=false
            guard.check("admin_tool", "do admin stuff");
        }
    }

    // ------------------------------------------------------------------
    // Client accessor tests for new APIs
    // ------------------------------------------------------------------

    @Test
    void testBuilderIncludesNewApis() {
        AgentTrustClient client = AgentTrustClient.builder().build();
        assertNotNull(client.sessions());
        assertNotNull(client.approvals());
        assertNotNull(client.agentCards());
        assertNotNull(client.a2a());
        assertNotNull(client.mcp());
        assertNotNull(client.delegations());
        assertNotNull(client.federation());
        assertNotNull(client.streaming());
        assertNotNull(client.wimse());
        client.close();
    }

    // ------------------------------------------------------------------
    // JSON utility tests
    // ------------------------------------------------------------------

    @Test
    void testJsonRoundTrip() {
        Map<String, Object> original = new LinkedHashMap<>();
        original.put("string", "hello");
        original.put("number", 42);
        original.put("float", 3.14);
        original.put("bool", true);
        original.put("null_val", null);
        original.put("array", List.of("a", "b", "c"));

        Map<String, Object> nested = new LinkedHashMap<>();
        nested.put("key", "value");
        original.put("nested", nested);

        String json = JsonUtil.serialize(original);
        Map<String, Object> parsed = JsonUtil.parse(json);

        assertEquals("hello", parsed.get("string"));
        assertEquals(42, parsed.get("number"));
        assertTrue(parsed.get("bool") instanceof Boolean);
        assertTrue((Boolean) parsed.get("bool"));
        assertNull(parsed.get("null_val"));

        @SuppressWarnings("unchecked")
        List<Object> arr = (List<Object>) parsed.get("array");
        assertEquals(3, arr.size());
        assertEquals("a", arr.get(0));

        @SuppressWarnings("unchecked")
        Map<String, Object> nest = (Map<String, Object>) parsed.get("nested");
        assertEquals("value", nest.get("key"));
    }

    @Test
    void testJsonEscaping() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("escaped", "line1\nline2\ttab \"quoted\" back\\slash");
        String json = JsonUtil.serialize(map);
        Map<String, Object> parsed = JsonUtil.parse(json);
        assertEquals("line1\nline2\ttab \"quoted\" back\\slash", parsed.get("escaped"));
    }

    // ------------------------------------------------------------------
    // Model tests
    // ------------------------------------------------------------------

    @Test
    void testTokenExpiry() {
        // Create a token that expires far in the future
        Token futureToken = new Token("at_future", "agent-1", List.of("read"), List.of(),
                java.time.Instant.now(), java.time.Instant.now().plusSeconds(3600), "tok-1");
        assertFalse(futureToken.isExpired());
        assertTrue(futureToken.ttlSeconds() > 0);

        // Create a token that already expired
        Token expiredToken = new Token("at_expired", "agent-1", List.of("read"), List.of(),
                java.time.Instant.now().minusSeconds(7200),
                java.time.Instant.now().minusSeconds(3600), "tok-2");
        assertTrue(expiredToken.isExpired());
        assertEquals(0, expiredToken.ttlSeconds());
    }
}
