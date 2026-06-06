package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.exceptions.NotFoundException;
import id.agenttrust.sdk.models.SIEMDestination;
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

class StreamingAPITest {

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
    void testCreate() throws AgentTrustException {
        handlers.put("/api/v1/siem/destinations", ex -> {
            assertEquals("POST", ex.getRequestMethod());
            jsonResponse(ex, 200,
                    "{\"id\":\"d1\",\"name\":\"splunk-prod\"," +
                            "\"destination_type\":\"splunk\"," +
                            "\"endpoint_url\":\"https://siem.example.com\"," +
                            "\"is_active\":true,\"batch_size\":100," +
                            "\"flush_interval_seconds\":30}");
        });
        try (AgentTrustClient client = startServer()) {
            SIEMDestination d = client.streaming().create(
                    StreamingAPI.CreateDestinationRequest.builder()
                            .name("splunk-prod")
                            .destinationType("splunk")
                            .endpointUrl("https://siem.example.com")
                            .authToken("secret")
                            .batchSize(100)
                            .flushIntervalSeconds(30)
                            .build()
            );
            assertEquals("d1", d.getId());
            assertEquals("splunk", d.getDestinationType());
            assertTrue(d.isActive());
            assertEquals(100, d.getBatchSize());
        }
    }

    @Test
    void testList() throws AgentTrustException {
        handlers.put("/api/v1/siem/destinations", ex ->
                jsonResponse(ex, 200,
                        "{\"destinations\":[" +
                                "{\"id\":\"d1\",\"name\":\"a\",\"destination_type\":\"splunk\"," +
                                "\"endpoint_url\":\"u1\",\"is_active\":true}," +
                                "{\"id\":\"d2\",\"name\":\"b\",\"destination_type\":\"datadog\"," +
                                "\"endpoint_url\":\"u2\",\"is_active\":false}]}")
        );
        try (AgentTrustClient client = startServer()) {
            List<SIEMDestination> list = client.streaming().list();
            assertEquals(2, list.size());
            assertFalse(list.get(1).isActive());
        }
    }

    @Test
    void testGet() throws AgentTrustException {
        handlers.put("/api/v1/siem/destinations/d1", ex ->
                jsonResponse(ex, 200,
                        "{\"id\":\"d1\",\"name\":\"splunk\"," +
                                "\"destination_type\":\"splunk\"," +
                                "\"endpoint_url\":\"u1\",\"is_active\":true}")
        );
        try (AgentTrustClient client = startServer()) {
            SIEMDestination d = client.streaming().get("d1");
            assertEquals("d1", d.getId());
        }
    }

    @Test
    void testUpdate() throws AgentTrustException {
        handlers.put("/api/v1/siem/destinations/d1", ex -> {
            assertEquals("PUT", ex.getRequestMethod());
            jsonResponse(ex, 200,
                    "{\"id\":\"d1\",\"name\":\"renamed\"," +
                            "\"destination_type\":\"splunk\"," +
                            "\"endpoint_url\":\"u1\",\"is_active\":false}");
        });
        try (AgentTrustClient client = startServer()) {
            SIEMDestination d = client.streaming().update("d1",
                    StreamingAPI.UpdateDestinationRequest.builder()
                            .name("renamed")
                            .isActive(false)
                            .build());
            assertEquals("renamed", d.getName());
            assertFalse(d.isActive());
        }
    }

    @Test
    void testDelete() throws AgentTrustException {
        final boolean[] called = {false};
        handlers.put("/api/v1/siem/destinations/d1", ex -> {
            assertEquals("DELETE", ex.getRequestMethod());
            called[0] = true;
            jsonResponse(ex, 200, "{}");
        });
        try (AgentTrustClient client = startServer()) {
            client.streaming().delete("d1");
            assertTrue(called[0]);
        }
    }

    @Test
    void testGetNotFound() {
        handlers.put("/api/v1/siem/destinations/missing", ex ->
                jsonResponse(ex, 404, "{\"message\":\"not found\"}")
        );
        try (AgentTrustClient client = startServer()) {
            assertThrows(NotFoundException.class, () -> client.streaming().get("missing"));
        }
    }
}
