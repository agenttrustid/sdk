package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.models.Agent;
import id.agenttrust.sdk.models.CreateAgentRequest;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AgentsAPITest {

    private static final String AGENT_RESPONSE =
            "{\"agent\":{\"id\":\"a\",\"name\":\"n\",\"org_id\":\"o\","
                    + "\"framework\":\"custom\",\"status\":\"active\",\"capabilities\":[]}}";

    private HttpServer server;
    private String baseUrl;

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        baseUrl = "http://localhost:" + server.getAddress().getPort();
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    private void respond(HttpExchange ex, AtomicReference<String> capturedBody) throws IOException {
        capturedBody.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
        byte[] bytes = AGENT_RESPONSE.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Test
    void createGeneratesAndRegistersOnlyPublicKey() throws AgentTrustException {
        AtomicReference<String> sentBody = new AtomicReference<>("");
        server.createContext("/api/v1/agents", ex -> respond(ex, sentBody));
        server.start();
        AgentTrustClient client = AgentTrustClient.builder().baseUrl(baseUrl).build();

        Agent agent = client.agents().create(CreateAgentRequest.builder().name("n").build());

        assertTrue(sentBody.get().contains("public_key"));
        assertTrue(sentBody.get().contains("BEGIN PUBLIC KEY"));
        assertFalse(sentBody.get().contains("BEGIN PRIVATE KEY")); // private key never sent
        assertNotNull(agent.getPrivateKey());
        assertTrue(agent.getPrivateKey().contains("BEGIN PRIVATE KEY"));
    }

    @Test
    void createWithSuppliedPublicKeyDoesNotGenerate() throws AgentTrustException {
        AgentKeys.AgentKeyPair kp = AgentKeys.generateAgentKey();
        AtomicReference<String> sentBody = new AtomicReference<>("");
        server.createContext("/api/v1/agents", ex -> respond(ex, sentBody));
        server.start();
        AgentTrustClient client = AgentTrustClient.builder().baseUrl(baseUrl).build();

        Agent agent = client.agents().create(
                CreateAgentRequest.builder().name("n").publicKey(kp.publicKeyPem()).build());

        assertTrue(sentBody.get().contains("public_key"));
        assertNull(agent.getPrivateKey()); // nothing generated locally
    }
}
