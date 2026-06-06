package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.exceptions.NotFoundException;
import id.agenttrust.sdk.models.AgentCard;
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
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AgentCardsAPITest {

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

    /** A representative A2A v1.0 agent card. */
    private static String agentCardJson() {
        return "{" +
                "\"name\":\"my-agent\"," +
                "\"description\":\"An example agent\"," +
                "\"version\":\"1.0\"," +
                "\"supportedInterfaces\":[" +
                "  {\"url\":\"https://agents.example.com/my-agent\",\"protocolBinding\":\"JSONRPC\",\"protocolVersion\":\"1.0\",\"tenant\":\"acme\"}," +
                "  {\"url\":\"https://backup.example.com/my-agent\",\"protocolBinding\":\"GRPC\",\"protocolVersion\":\"1.0\"}" +
                "]," +
                "\"provider\":{\"organization\":\"ACME\",\"url\":\"https://acme.com\"}," +
                "\"capabilities\":{" +
                "  \"streaming\":true," +
                "  \"pushNotifications\":false," +
                "  \"extendedAgentCard\":true," +
                "  \"extensions\":[" +
                "    {\"uri\":\"https://agenttrust.id/ext/trust/v1\",\"description\":\"trust\",\"required\":false,\"params\":{\"ati_trust_score\":90,\"ati_guardian_tier\":\"deep\"}}" +
                "  ]" +
                "}," +
                "\"securitySchemes\":{\"bearerAuth\":{\"type\":\"http\",\"scheme\":\"bearer\"}}," +
                "\"securityRequirements\":[{\"bearerAuth\":[]}]," +
                "\"defaultInputModes\":[\"text/plain\"]," +
                "\"defaultOutputModes\":[\"text/plain\",\"application/json\"]," +
                "\"skills\":[" +
                "  {\"id\":\"s1\",\"name\":\"search\",\"description\":\"web search\",\"tags\":[\"web\",\"retrieval\"],\"examples\":[\"find X\"],\"inputModes\":[\"text/plain\"],\"outputModes\":[\"application/json\"]}" +
                "]," +
                "\"signatures\":[{\"protected\":\"eyJhbGciOiJFZERTQSJ9\",\"signature\":\"abc123\",\"header\":{\"kid\":\"key-1\"}}]," +
                "\"documentationUrl\":\"https://docs.example.com\"," +
                "\"iconUrl\":\"https://example.com/icon.png\"" +
                "}";
    }

    /** A pre-v1.0 card with only a top-level url and a security_policy block. */
    private static String legacyCardJson() {
        return "{\"name\":\"legacy-agent\",\"url\":\"https://legacy.example.com/agent\"," +
                "\"version\":\"0.9\"," +
                "\"capabilities\":{\"streaming\":false,\"push_notifications\":true}," +
                "\"skills\":[{\"id\":\"l1\",\"name\":\"echo\"}]}";
    }

    @Test
    void testGenerate() throws AgentTrustException {
        handlers.put("/api/v1/agents/agent-1/card", ex -> {
            assertEquals("POST", ex.getRequestMethod());
            jsonResponse(ex, 200, agentCardJson());
        });
        try (AgentTrustClient client = startServer()) {
            AgentCard card = client.agentCards().generate("agent-1");
            assertEquals("my-agent", card.getName());
            assertEquals("An example agent", card.getDescription());
            assertEquals("1.0", card.getVersion());
            assertEquals("ACME", card.getProviderOrganization());

            // v1.0 trust extension drives getTrustScore()
            assertEquals(90, card.getTrustScore());

            // primary URL comes from the first supported interface
            assertEquals("https://agents.example.com/my-agent", card.getPrimaryUrl());
            assertEquals(2, card.getSupportedInterfaces().size());
            assertEquals("JSONRPC", card.getSupportedInterfaces().get(0).getProtocolBinding());
            assertEquals("acme", card.getSupportedInterfaces().get(0).getTenant());

            // capabilities
            assertTrue(card.getCapabilities().isStreaming());
            assertFalse(card.getCapabilities().isPushNotifications());
            assertEquals(Boolean.TRUE, card.getCapabilities().getExtendedAgentCard());
            assertEquals(1, card.getCapabilities().getExtensions().size());

            // skills + tags
            assertEquals(1, card.getSkills().size());
            assertEquals("search", card.getSkills().get(0).getName());
            assertEquals(2, card.getSkills().get(0).getTags().size());
            assertTrue(card.getSkills().get(0).getTags().contains("retrieval"));
            assertEquals(1, card.getSkills().get(0).getExamples().size());
        }
    }

    @Test
    void testGet() throws AgentTrustException {
        handlers.put("/api/v1/agents/agent-1/card", ex -> {
            assertEquals("GET", ex.getRequestMethod());
            jsonResponse(ex, 200, agentCardJson());
        });
        try (AgentTrustClient client = startServer()) {
            AgentCard card = client.agentCards().get("agent-1");

            // securitySchemes + requirements
            assertTrue(card.getSecuritySchemes().containsKey("bearerAuth"));
            assertEquals("http", card.getSecuritySchemes().get("bearerAuth").getType());
            assertEquals("bearer", card.getSecuritySchemes().get("bearerAuth").getScheme());
            assertEquals(1, card.getSecurityRequirements().size());
            assertTrue(card.getSecurityRequirements().get(0).containsKey("bearerAuth"));

            // I/O modes
            assertEquals(1, card.getDefaultInputModes().size());
            assertEquals(2, card.getDefaultOutputModes().size());

            // signatures
            assertEquals(1, card.getSignatures().size());
            assertEquals("abc123", card.getSignatures().get(0).getSignature());
            assertEquals("key-1", card.getSignatures().get(0).getHeader().get("kid"));

            assertEquals("https://docs.example.com", card.getDocumentationUrl());
            assertEquals("https://example.com/icon.png", card.getIconUrl());
        }
    }

    @Test
    void testPublish() throws AgentTrustException {
        handlers.put("/api/v1/agents/agent-1/card/publish", ex -> {
            assertEquals("PUT", ex.getRequestMethod());
            jsonResponse(ex, 200, agentCardJson());
        });
        try (AgentTrustClient client = startServer()) {
            AgentCard card = client.agentCards().publish("agent-1");
            assertEquals("my-agent", card.getName());
        }
    }

    @Test
    void testGetPublic() throws AgentTrustException {
        handlers.put("/a2a/agents/agent-1/agent.json", ex ->
                jsonResponse(ex, 200, agentCardJson())
        );
        try (AgentTrustClient client = startServer()) {
            AgentCard card = client.agentCards().getPublic("agent-1");
            assertEquals("my-agent", card.getName());
            assertEquals("https://agents.example.com/my-agent", card.getPrimaryUrl());
        }
    }

    @Test
    void testLegacyCardStillParses() throws AgentTrustException {
        handlers.put("/api/v1/agents/legacy/card", ex ->
                jsonResponse(ex, 200, legacyCardJson())
        );
        try (AgentTrustClient client = startServer()) {
            AgentCard card = client.agentCards().get("legacy");
            // No supportedInterfaces: getPrimaryUrl() falls back to legacy url
            assertTrue(card.getSupportedInterfaces().isEmpty());
            assertEquals("https://legacy.example.com/agent", card.getPrimaryUrl());
            assertEquals("https://legacy.example.com/agent", card.getLegacyUrl());
            // No trust extension: getTrustScore() defaults to 0
            assertEquals(0, card.getTrustScore());
            // No signatures: empty, not null
            assertTrue(card.getSignatures().isEmpty());
            // Skill with no tags defaults to empty list
            assertEquals(1, card.getSkills().size());
            assertTrue(card.getSkills().get(0).getTags().isEmpty());
        }
    }

    @Test
    void testEmptyCardDoesNotThrow() {
        // fromJson must default gracefully when url/supportedInterfaces/signatures absent
        AgentCard card = AgentCard.fromJson(new LinkedHashMap<>());
        assertNotNull(card);
        assertNull(card.getPrimaryUrl());
        assertEquals(0, card.getTrustScore());
        assertTrue(card.getSkills().isEmpty());
        assertTrue(card.getSupportedInterfaces().isEmpty());
        assertNotNull(card.getCapabilities());
    }

    @Test
    void testGetNotFound() {
        handlers.put("/api/v1/agents/missing/card", ex ->
                jsonResponse(ex, 404, "{\"message\":\"not found\"}")
        );
        try (AgentTrustClient client = startServer()) {
            assertThrows(NotFoundException.class, () -> client.agentCards().get("missing"));
        }
    }
}
