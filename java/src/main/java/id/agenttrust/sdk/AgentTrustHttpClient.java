package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.*;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/**
 * Internal HTTP helper that wraps {@link java.net.http.HttpClient}.
 * <p>
 * Handles JSON serialization/deserialization, the {@code X-API-Key} header,
 * and maps HTTP error status codes to typed AgentTrust ID exceptions.
 * <p>
 * This class is package-private; external users interact with it only through
 * the public API classes.
 */
final class AgentTrustHttpClient {

    private final String baseUrl;
    private final String apiKey;
    private final HttpClient httpClient;
    private final Duration timeout;
    private final java.util.Map<String, String> extraHeaders = new java.util.concurrent.ConcurrentHashMap<>();

    AgentTrustHttpClient(String baseUrl, String apiKey, HttpClient httpClient, Duration timeout) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.apiKey = apiKey;
        this.httpClient = httpClient;
        this.timeout = timeout;
    }

    /** Sets a header that will be included on every subsequent request until removed. */
    void setHeader(String key, String value) {
        extraHeaders.put(key, value);
    }

    /** Removes a previously set header. */
    void removeHeader(String key) {
        extraHeaders.remove(key);
    }

    /** Returns the configured base URL (without trailing slash). */
    String getBaseUrl() {
        return baseUrl;
    }

    /** Returns the API key configured for this client, or {@code null}. */
    String getApiKey() {
        return apiKey;
    }

    /** Returns the request timeout. */
    Duration getTimeout() {
        return timeout;
    }

    /** Returns the underlying {@link HttpClient}. */
    HttpClient getHttpClient() {
        return httpClient;
    }

    /**
     * Sends a GET request and parses the JSON response.
     */
    Map<String, Object> get(String path) throws AgentTrustException {
        return request("GET", path, null);
    }

    /**
     * Sends a POST request with a JSON body and parses the JSON response.
     */
    Map<String, Object> post(String path, Map<String, Object> body) throws AgentTrustException {
        return request("POST", path, body);
    }

    /**
     * Sends a POST request with a JSON body plus additional per-request headers
     * (e.g. an agent WIMSE Bearer token + DPoP proof on runtime calls).
     */
    Map<String, Object> post(String path, Map<String, Object> body, Map<String, String> perRequestHeaders)
            throws AgentTrustException {
        return request("POST", path, body, perRequestHeaders);
    }

    /**
     * Sends a POST request with no body and parses the JSON response.
     */
    Map<String, Object> post(String path) throws AgentTrustException {
        return request("POST", path, null);
    }

    /**
     * Sends a PUT request with a JSON body and parses the JSON response.
     */
    Map<String, Object> put(String path, Map<String, Object> body) throws AgentTrustException {
        return request("PUT", path, body);
    }

    /**
     * Sends a PUT request with no body and parses the JSON response.
     */
    Map<String, Object> put(String path) throws AgentTrustException {
        return request("PUT", path, null);
    }

    /**
     * Sends a DELETE request and parses the JSON response.
     */
    Map<String, Object> delete(String path) throws AgentTrustException {
        return request("DELETE", path, null);
    }

    /**
     * Sends a GET request and parses the response as a raw JSON value
     * (could be a Map, a List, etc.).
     */
    Object getRaw(String path) throws AgentTrustException {
        return requestRaw("GET", path, null);
    }

    /**
     * Sends an HTTP request and returns the raw JSON value (could be a List
     * or Map at the root). Used for endpoints that may return arrays directly.
     */
    Object requestRaw(String method, String path, Map<String, Object> body) throws AgentTrustException {
        String responseBody = sendAndCheck(method, path, body);
        if (responseBody == null || responseBody.isEmpty()) {
            return new java.util.LinkedHashMap<>();
        }
        try {
            return JsonUtil.parseValue(responseBody);
        } catch (Exception e) {
            throw new AgentTrustException("Failed to parse response: " + e.getMessage(),
                    "PARSE_ERROR", 200, e);
        }
    }

    /**
     * Sends an HTTP request, handling JSON encoding, API key headers, and
     * error mapping.
     */
    private Map<String, Object> request(String method, String path, Map<String, Object> body)
            throws AgentTrustException {
        return request(method, path, body, null);
    }

    private Map<String, Object> request(
            String method, String path, Map<String, Object> body, Map<String, String> perRequestHeaders)
            throws AgentTrustException {
        String responseBody = sendAndCheck(method, path, body, perRequestHeaders);

        // Parse response body
        if (responseBody != null && !responseBody.isEmpty()) {
            try {
                Object parsed = JsonUtil.parseValue(responseBody);
                if (parsed instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> casted = (Map<String, Object>) parsed;
                    return casted;
                }
                // Non-object response (e.g. array). Wrap in a map under "data"
                // so callers using the Map-returning helpers do not crash.
                Map<String, Object> wrapped = new java.util.LinkedHashMap<>();
                wrapped.put("data", parsed);
                return wrapped;
            } catch (Exception e) {
                throw new AgentTrustException("Failed to parse response: " + e.getMessage(),
                        "PARSE_ERROR", 200, e);
            }
        }
        return new java.util.LinkedHashMap<>();
    }

    /**
     * Sends the HTTP request and returns the response body as a string after
     * mapping non-2xx status codes to exceptions.
     */
    private String sendAndCheck(String method, String path, Map<String, Object> body)
            throws AgentTrustException {
        return sendAndCheck(method, path, body, null);
    }

    private String sendAndCheck(
            String method, String path, Map<String, Object> body, Map<String, String> perRequestHeaders)
            throws AgentTrustException {
        String url = baseUrl + path;

        HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .timeout(timeout);

        if (apiKey != null && !apiKey.isEmpty()) {
            reqBuilder.header("X-API-Key", apiKey);
        }

        for (Map.Entry<String, String> e : extraHeaders.entrySet()) {
            reqBuilder.header(e.getKey(), e.getValue());
        }

        if (perRequestHeaders != null) {
            for (Map.Entry<String, String> e : perRequestHeaders.entrySet()) {
                reqBuilder.header(e.getKey(), e.getValue());
            }
        }

        if ("GET".equals(method)) {
            reqBuilder.GET();
        } else if ("POST".equals(method)) {
            String jsonBody = body != null ? JsonUtil.serialize(body) : "{}";
            reqBuilder.POST(HttpRequest.BodyPublishers.ofString(jsonBody));
        } else if ("PUT".equals(method)) {
            String jsonBody = body != null ? JsonUtil.serialize(body) : "{}";
            reqBuilder.PUT(HttpRequest.BodyPublishers.ofString(jsonBody));
        } else if ("DELETE".equals(method)) {
            reqBuilder.DELETE();
        } else {
            String jsonBody = body != null ? JsonUtil.serialize(body) : "{}";
            reqBuilder.method(method, HttpRequest.BodyPublishers.ofString(jsonBody));
        }

        HttpResponse<String> response;
        try {
            response = httpClient.send(reqBuilder.build(), HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new NetworkException("Network error: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new NetworkException("Request interrupted: " + e.getMessage(), e);
        }

        int status = response.statusCode();
        String responseBody = response.body();

        // Check for HTTP errors
        if (status < 200 || status >= 300) {
            String message = "HTTP " + status + " error";
            if (responseBody != null && !responseBody.isEmpty()) {
                try {
                    Map<String, Object> errorData = JsonUtil.parse(responseBody);
                    String errorMsg = JsonUtil.getString(errorData, "message");
                    if (errorMsg != null && !errorMsg.isEmpty()) {
                        message = errorMsg;
                    }
                } catch (Exception ignored) {
                    // Use default message if parsing fails
                }
            }
            throw createErrorFromStatus(status, message);
        }

        return responseBody;
    }

    /**
     * Creates the appropriate typed exception based on the HTTP status code.
     */
    private static AgentTrustException createErrorFromStatus(int status, String message) {
        switch (status) {
            case 401:
                return new AuthenticationException(message);
            case 403:
                return new AuthorizationException(message);
            case 400:
                return new ValidationException(message);
            case 404:
                return new NotFoundException(message);
            default:
                return new AgentTrustException(message, "HTTP_" + status, status);
        }
    }
}
