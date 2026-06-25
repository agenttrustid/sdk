package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.models.HealthResponse;

import java.net.http.HttpClient;
import java.time.Duration;

/**
 * Main entry point for the AgentTrust Java SDK.
 * <p>
 * {@code AgentTrustClient} provides access to all AgentTrust ID services through typed sub-APIs:
 * <ul>
 *   <li>{@link #agents()} - Agent registration and lifecycle management</li>
 *   <li>{@link #tokens()} - Capability token issuance, verification, and revocation</li>
 *   <li>{@link #actions()} - Pre-flight action authorization checks</li>
 *   <li>{@link #telemetry()} - Agent behavior telemetry reporting</li>
 *   <li>{@link #sessions()} - MCP session initialization and management</li>
 *   <li>{@link #approvals()} - Elevated action approval management</li>
 *   <li>{@link #agentCards()} - A2A agent card discovery and publishing</li>
 *   <li>{@link #a2a()} - Agent-to-Agent task delegation (JSON-RPC 2.0)</li>
 *   <li>{@link #mcp()} - MCP server registration and proxy</li>
 *   <li>{@link #delegations()} - Capability delegation chains</li>
 *   <li>{@link #federation()} - Cross-org OIDC federation</li>
 *   <li>{@link #streaming()} - SIEM destination management</li>
 *   <li>{@link #wimse()} - WIMSE workload identity tokens</li>
 * </ul>
 *
 * <h2>Quick start</h2>
 * <pre>{@code
 * // Create client with builder
 * AgentTrustClient client = AgentTrustClient.builder()
 *     .baseUrl("http://localhost:8080")
 *     .apiKey("sk_live_xxx")
 *     .build();
 *
 * // Or create from environment variables
 * AgentTrustClient client = AgentTrustClient.fromEnv();
 *
 * // Check service health
 * HealthResponse health = client.health();
 *
 * // Create an agent
 * Agent agent = client.agents().create(
 *     CreateAgentRequest.builder()
 *         .name("my-agent")
 *         .framework("langchain")
 *         .capabilities(List.of("files:read", "web:fetch"))
 *         .build()
 * );
 * }</pre>
 *
 * <p>Implements {@link AutoCloseable} for proper resource cleanup of the
 * underlying HTTP client.
 */
public class AgentTrustClient implements AutoCloseable {

    /** Default gateway URL. */
    public static final String DEFAULT_BASE_URL = "http://localhost:8080";
    /** Default request timeout. */
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    /**
     * Package-private env reader, default {@link System#getenv(String)}.
     * Tests override this to inject a deterministic map.
     */
    static java.util.function.Function<String, String> envReader = System::getenv;

    private final AgentTrustHttpClient httpClient;
    private final AgentsAPI agents;
    private final TokensAPI tokens;
    private final ActionsAPI actions;
    private final TelemetryAPI telemetry;
    private final SessionsAPI sessions;
    private final ApprovalsAPI approvals;
    private final AgentCardsAPI agentCards;
    private final A2AAPI a2a;
    private final MCPAPI mcp;
    private final DelegationsAPI delegations;
    private final FederationAPI federation;
    private final StreamingAPI streaming;
    private final WIMSEAPI wimse;

    private AgentTrustClient(AgentTrustHttpClient httpClient) {
        this.httpClient = httpClient;
        this.agents = new AgentsAPI(httpClient);
        this.tokens = new TokensAPI(httpClient);
        this.actions = new ActionsAPI(httpClient);
        this.telemetry = new TelemetryAPI(httpClient);
        this.sessions = new SessionsAPI(httpClient);
        this.approvals = new ApprovalsAPI(httpClient);
        this.agentCards = new AgentCardsAPI(httpClient);
        this.a2a = new A2AAPI(httpClient);
        this.mcp = new MCPAPI(httpClient);
        this.delegations = new DelegationsAPI(httpClient);
        this.federation = new FederationAPI(httpClient);
        this.streaming = new StreamingAPI(httpClient);
        this.wimse = new WIMSEAPI(httpClient);
    }

    /**
     * Creates a new {@link Builder} for configuring an {@code AgentTrustClient}.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Creates an {@code AgentTrustClient} from environment variables.
     *
     * Preferred variables:
     * <ul>
     *   <li>{@code AGENTTRUST_URL} - Gateway URL (fallback: {@code AGENTTRUST_BASE_URL}, default: http://localhost:8080)</li>
     *   <li>{@code AGENTTRUST_API_KEY} - Organization API key (sk_live_xxx)</li>
     * </ul>
     *
     */
    public static AgentTrustClient fromEnv() {
        String baseUrl = readEnv("AGENTTRUST_URL");
        if (baseUrl == null || baseUrl.isEmpty()) {
            baseUrl = readEnv("AGENTTRUST_BASE_URL");
        }
        if (baseUrl == null || baseUrl.isEmpty()) {
            baseUrl = DEFAULT_BASE_URL;
        }
        String apiKey = readEnv("AGENTTRUST_API_KEY");
        Builder builder = builder().baseUrl(baseUrl);
        if (apiKey != null && !apiKey.isEmpty()) {
            builder.apiKey(apiKey);
        }
        return builder.build();
    }

    private static String readEnv(String key) {
        String v = envReader.apply(key);
        return (v != null && !v.isEmpty()) ? v : null;
    }

    /** Returns the configured gateway base URL. */
    public String getBaseUrl() {
        return httpClient.getBaseUrl();
    }

    /**
     * Checks the AgentTrust ID service health.
     *
     * @return the health response
     * @throws AgentTrustException if the request fails
     */
    public HealthResponse health() throws AgentTrustException {
        var result = httpClient.get("/health");
        return HealthResponse.fromJson(result);
    }

    /** Returns the agent management API. */
    public AgentsAPI agents() {
        return agents;
    }

    /** Returns the token management API. */
    public TokensAPI tokens() {
        return tokens;
    }

    /** Returns the action check API. */
    public ActionsAPI actions() {
        return actions;
    }

    /**
     * Routes runtime authorization checks ({@code actions().check}) through an
     * agent's WIMSE token plus a per-request DPoP proof, in addition to any org
     * API key. Build the credentials with {@link AgentCredentials}.
     *
     * @param credentials the agent runtime credentials
     */
    public void useAgentCredentials(AgentCredentials credentials) {
        actions.setAgentCredentials(credentials);
    }

    /** Returns the telemetry reporting API. */
    public TelemetryAPI telemetry() {
        return telemetry;
    }

    /** Returns the MCP session management API. */
    public SessionsAPI sessions() {
        return sessions;
    }

    /** Returns the approval management API. */
    public ApprovalsAPI approvals() {
        return approvals;
    }

    /** Returns the A2A agent card API. */
    public AgentCardsAPI agentCards() {
        return agentCards;
    }

    /** Returns the Agent-to-Agent task dispatch API. */
    public A2AAPI a2a() {
        return a2a;
    }

    /** Returns the MCP server proxy API. */
    public MCPAPI mcp() {
        return mcp;
    }

    /** Returns the capability delegation API. */
    public DelegationsAPI delegations() {
        return delegations;
    }

    /** Returns the OIDC federation API. */
    public FederationAPI federation() {
        return federation;
    }

    /** Returns the SIEM destination management API. */
    public StreamingAPI streaming() {
        return streaming;
    }

    /** Returns the WIMSE workload identity API. */
    public WIMSEAPI wimse() {
        return wimse;
    }

    /**
     * Closes the underlying HTTP client.
     */
    @Override
    public void close() {
        // java.net.http.HttpClient does not implement Closeable, but we
        // provide this method so AgentTrustClient can be used with try-with-resources.
    }

    // ------------------------------------------------------------------
    // Builder
    // ------------------------------------------------------------------

    /**
     * Builder for configuring and constructing an {@link AgentTrustClient}.
     */
    public static class Builder {
        private String baseUrl = DEFAULT_BASE_URL;
        private String apiKey;
        private Duration timeout = DEFAULT_TIMEOUT;
        private HttpClient httpClient;

        private Builder() {
        }

        /**
         * Sets the AgentTrust ID gateway base URL.
         *
         * @param url base URL (default: "http://localhost:8080")
         * @return this builder
         */
        public Builder baseUrl(String url) {
            this.baseUrl = url;
            return this;
        }

        /**
         * Sets the organization API key (e.g. "sk_live_xxx").
         * The key is sent as an {@code X-API-Key} header on all requests.
         *
         * @param key API key
         * @return this builder
         */
        public Builder apiKey(String key) {
            this.apiKey = key;
            return this;
        }

        /**
         * Sets the HTTP request timeout.
         *
         * @param timeout request timeout (default: 30 seconds)
         * @return this builder
         */
        public Builder timeout(Duration timeout) {
            this.timeout = timeout;
            return this;
        }

        /**
         * Sets a custom {@link HttpClient} for all API requests.
         * When provided, the timeout set via {@link #timeout(Duration)} is
         * still applied at the request level.
         *
         * @param httpClient custom HTTP client
         * @return this builder
         */
        public Builder httpClient(HttpClient httpClient) {
            this.httpClient = httpClient;
            return this;
        }

        /**
         * Builds the {@link AgentTrustClient}.
         */
        public AgentTrustClient build() {
            return new AgentTrustClient(buildHttpClient());
        }

        private AgentTrustHttpClient buildHttpClient() {
            HttpClient client = this.httpClient;
            if (client == null) {
                client = HttpClient.newBuilder()
                        .connectTimeout(timeout)
                        .build();
            }
            return new AgentTrustHttpClient(baseUrl, apiKey, client, timeout);
        }
    }
}
