package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.exceptions.NotFoundException;
import id.agenttrust.sdk.models.MCPServer;
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

class MCPAPITest {

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
    void testRegisterServer() throws AgentTrustException {
        handlers.put("/mcp/servers", ex -> {
            assertEquals("POST", ex.getRequestMethod());
            jsonResponse(ex, 200,
                    "{\"id\":\"srv-1\",\"name\":\"fs\",\"url\":\"mcp://files\"," +
                            "\"capabilities\":[\"read\",\"write\"]," +
                            "\"created_at\":\"2026-01-01T00:00:00Z\"}");
        });
        try (AgentTrustClient client = startServer()) {
            MCPServer s = client.mcp().registerServer("fs", "mcp://files",
                    List.of("read", "write"));
            assertEquals("srv-1", s.getId());
            assertEquals("fs", s.getName());
            assertEquals(2, s.getCapabilities().size());
        }
    }

    @Test
    void testListServersWrappedResponse() throws AgentTrustException {
        handlers.put("/mcp/servers", ex -> {
            assertEquals("GET", ex.getRequestMethod());
            jsonResponse(ex, 200,
                    "{\"servers\":[" +
                            "{\"id\":\"s1\",\"name\":\"a\",\"url\":\"u1\"}," +
                            "{\"id\":\"s2\",\"name\":\"b\",\"url\":\"u2\"}]}");
        });
        try (AgentTrustClient client = startServer()) {
            List<MCPServer> servers = client.mcp().listServers();
            assertEquals(2, servers.size());
            assertEquals("s1", servers.get(0).getId());
            assertEquals("b", servers.get(1).getName());
        }
    }

    @Test
    void testListServersBareArray() throws AgentTrustException {
        handlers.put("/mcp/servers", ex ->
                jsonResponse(ex, 200,
                        "[{\"id\":\"s1\",\"name\":\"only\",\"url\":\"u1\"}]")
        );
        try (AgentTrustClient client = startServer()) {
            List<MCPServer> servers = client.mcp().listServers();
            assertEquals(1, servers.size());
            assertEquals("only", servers.get(0).getName());
        }
    }

    @Test
    void testRemoveServer() throws AgentTrustException {
        final boolean[] called = {false};
        handlers.put("/mcp/servers/srv-1", ex -> {
            assertEquals("DELETE", ex.getRequestMethod());
            called[0] = true;
            jsonResponse(ex, 200, "{}");
        });
        try (AgentTrustClient client = startServer()) {
            client.mcp().removeServer("srv-1");
            assertTrue(called[0]);
        }
    }

    @Test
    void testCallToolWithSessionId() throws AgentTrustException {
        final String[] receivedAgentId = {null};
        final String[] receivedSessionId = {null};
        final String[] receivedMethod = {null};

        handlers.put("/mcp/srv-1", ex -> {
            receivedAgentId[0] = ex.getRequestHeaders().getFirst("X-Agent-ID");
            receivedSessionId[0] = ex.getRequestHeaders().getFirst("X-Session-ID");
            String body = readBody(ex);
            Map<String, Object> req = JsonUtil.parse(body);
            receivedMethod[0] = (String) req.get("method");
            jsonResponse(ex, 200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"value\":42}}");
        });

        try (AgentTrustClient client = startServer()) {
            Object result = client.mcp().callTool("srv-1", "agent-1", "tools/call",
                    Map.of("name", "test"), "sess-1");
            assertEquals("agent-1", receivedAgentId[0]);
            assertEquals("sess-1", receivedSessionId[0]);
            assertEquals("tools/call", receivedMethod[0]);
            assertTrue(result instanceof Map);
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) result;
            assertEquals(42, m.get("value"));
        }
    }

    @Test
    void testCallToolRequiresAgentId() {
        try (AgentTrustClient client = startServer()) {
            assertThrows(IllegalArgumentException.class,
                    () -> client.mcp().callTool("srv-1", "", "tools/list", null));
        }
    }

    @Test
    void testGetServerNotFound() {
        handlers.put("/mcp/servers/missing", ex ->
                jsonResponse(ex, 404, "{\"message\":\"not found\"}")
        );
        try (AgentTrustClient client = startServer()) {
            assertThrows(NotFoundException.class, () -> client.mcp().getServer("missing"));
        }
    }
}
