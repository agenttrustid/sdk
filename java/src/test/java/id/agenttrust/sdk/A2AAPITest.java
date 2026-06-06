package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.models.A2ATask;
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

class A2AAPITest {

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
    void testSendTask() throws AgentTrustException {
        final String[] receivedMethod = {null};
        handlers.put("/a2a", ex -> {
            String body = readBody(ex);
            Map<String, Object> req = JsonUtil.parse(body);
            receivedMethod[0] = (String) req.get("method");
            jsonResponse(ex, 200,
                    "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{" +
                            "\"id\":\"task-1\"," +
                            "\"source_agent_id\":\"a1\"," +
                            "\"target_agent_id\":\"a2\"," +
                            "\"status\":\"queued\"," +
                            "\"created_at\":\"2026-01-01T00:00:00Z\"," +
                            "\"updated_at\":\"2026-01-01T00:00:00Z\"}}");
        });

        try (AgentTrustClient client = startServer()) {
            Map<String, Object> message = new LinkedHashMap<>();
            message.put("text", "do something");
            A2ATask task = client.a2a().sendTask("a1", "a2", message);
            assertEquals("task-1", task.getId());
            assertEquals("a1", task.getSourceAgentId());
            assertEquals("a2", task.getTargetAgentId());
            assertEquals("queued", task.getStatus());
            assertEquals("tasks/send", receivedMethod[0]);
        }
    }

    @Test
    void testGetTask() throws AgentTrustException {
        handlers.put("/a2a", ex -> {
            jsonResponse(ex, 200,
                    "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{" +
                            "\"id\":\"task-1\",\"status\":\"completed\"," +
                            "\"source_agent_id\":\"a1\",\"target_agent_id\":\"a2\"}}");
        });

        try (AgentTrustClient client = startServer()) {
            A2ATask task = client.a2a().getTask("task-1");
            assertEquals("task-1", task.getId());
            assertEquals("completed", task.getStatus());
        }
    }

    @Test
    void testCancelTask() throws AgentTrustException {
        handlers.put("/a2a", ex -> {
            jsonResponse(ex, 200,
                    "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{" +
                            "\"id\":\"task-1\",\"status\":\"cancelled\"}}");
        });

        try (AgentTrustClient client = startServer()) {
            A2ATask task = client.a2a().cancelTask("task-1");
            assertEquals("cancelled", task.getStatus());
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void testSendMessage() throws AgentTrustException {
        final String[] receivedMethod = {null};
        final Map<String, Object>[] receivedParams = new Map[]{null};
        handlers.put("/a2a/agents/agent-x", ex -> {
            assertEquals("POST", ex.getRequestMethod());
            String body = readBody(ex);
            Map<String, Object> req = JsonUtil.parse(body);
            receivedMethod[0] = (String) req.get("method");
            receivedParams[0] = (Map<String, Object>) req.get("params");
            jsonResponse(ex, 200,
                    "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{" +
                            "\"id\":\"task-9\"," +
                            "\"contextId\":\"ctx-1\"," +
                            "\"status\":{\"state\":\"completed\",\"timestamp\":\"2026-01-01T00:00:00Z\"}," +
                            "\"history\":[{\"role\":\"user\",\"parts\":[{\"kind\":\"text\",\"text\":\"hi\"}]}]," +
                            "\"artifacts\":[{\"artifactId\":\"a1\",\"parts\":[]}]}}");
        });

        try (AgentTrustClient client = startServer()) {
            A2ATask task = client.a2a().sendMessage("agent-x", "hi", "msg-1", "task-9");
            assertEquals("task-9", task.getId());
            assertEquals("ctx-1", task.getContextId());
            assertEquals("completed", task.getStatus());
            assertNotNull(task.getStatusObject());
            assertEquals("completed", task.getStatusObject().getState());
            assertEquals("2026-01-01T00:00:00Z", task.getStatusObject().getTimestamp());
            assertEquals(1, task.getHistory().size());
            assertEquals(1, task.getArtifacts().size());

            // verify the JSON-RPC envelope sent to the per-agent endpoint
            assertEquals("message/send", receivedMethod[0]);
            Map<String, Object> message = (Map<String, Object>) receivedParams[0].get("message");
            assertEquals("user", message.get("role"));
            assertEquals("msg-1", message.get("messageId"));
            assertEquals("task-9", message.get("taskId"));
            java.util.List<Object> parts = (java.util.List<Object>) message.get("parts");
            assertEquals(1, parts.size());
            Map<String, Object> part = (Map<String, Object>) parts.get(0);
            assertEquals("text", part.get("kind"));
            assertEquals("hi", part.get("text"));
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void testSendMessageWithoutTaskId() throws AgentTrustException {
        final Map<String, Object>[] receivedParams = new Map[]{null};
        handlers.put("/a2a/agents/agent-y", ex -> {
            String body = readBody(ex);
            Map<String, Object> req = JsonUtil.parse(body);
            receivedParams[0] = (Map<String, Object>) req.get("params");
            jsonResponse(ex, 200,
                    "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{" +
                            "\"id\":\"task-10\",\"status\":{\"state\":\"submitted\"}}}");
        });

        try (AgentTrustClient client = startServer()) {
            A2ATask task = client.a2a().sendMessage("agent-y", "start", "msg-2", null);
            assertEquals("task-10", task.getId());
            assertEquals("submitted", task.getStatus());

            Map<String, Object> message = (Map<String, Object>) receivedParams[0].get("message");
            // taskId must be omitted when null
            assertFalse(message.containsKey("taskId"));
        }
    }

    @Test
    void testJsonRpcError() {
        handlers.put("/a2a", ex ->
                jsonResponse(ex, 200,
                        "{\"jsonrpc\":\"2.0\",\"id\":\"1\"," +
                                "\"error\":{\"code\":-32601,\"message\":\"method not found\"}}")
        );

        try (AgentTrustClient client = startServer()) {
            AgentTrustException ex = assertThrows(AgentTrustException.class,
                    () -> client.a2a().getTask("missing"));
            assertTrue(ex.getMessage().contains("method not found"));
            assertTrue(ex.getCode().startsWith("A2A_ERROR_"));
        }
    }
}
