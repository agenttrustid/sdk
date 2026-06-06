package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.models.FederationProvider;
import id.agenttrust.sdk.models.Session;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Federation API — register external OIDC providers, verify federated tokens,
 * and bridge them to AgentTrust ID sessions.
 * <p>
 * Obtain an instance via {@link AgentTrustClient#federation()}.
 */
public class FederationAPI {

    private final AgentTrustHttpClient httpClient;

    FederationAPI(AgentTrustHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Registers a new federation OIDC provider.
     *
     * @param issuer     the OIDC issuer URL
     * @param name       the human-readable provider name
     * @param trustLevel the trust level for tokens issued by this provider
     *                   (may be {@code null} for default)
     * @return the registered provider
     * @throws AgentTrustException if the request fails
     */
    public FederationProvider registerProvider(String issuer, String name, String trustLevel)
            throws AgentTrustException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("issuer", issuer);
        body.put("name", name);
        if (trustLevel != null) body.put("trust_level", trustLevel);
        Map<String, Object> result = httpClient.post("/api/v1/federation/providers", body);
        return FederationProvider.fromJson(result);
    }

    /**
     * Lists all registered federation providers.
     *
     * @return list of providers (possibly empty)
     * @throws AgentTrustException if the request fails
     */
    @SuppressWarnings("unchecked")
    public List<FederationProvider> listProviders() throws AgentTrustException {
        Object raw = httpClient.getRaw("/api/v1/federation/providers");
        List<Object> rawList;
        if (raw instanceof List) {
            rawList = (List<Object>) raw;
        } else if (raw instanceof Map) {
            Map<String, Object> wrapper = (Map<String, Object>) raw;
            Object items = wrapper.get("providers");
            rawList = items instanceof List ? (List<Object>) items : new ArrayList<>();
        } else {
            rawList = new ArrayList<>();
        }
        List<FederationProvider> out = new ArrayList<>();
        for (Object item : rawList) {
            if (item instanceof Map) {
                out.add(FederationProvider.fromJson((Map<String, Object>) item));
            }
        }
        return out;
    }

    /**
     * Removes a registered federation provider.
     *
     * @param providerId the provider identifier
     * @throws AgentTrustException if the request fails
     */
    public void deleteProvider(String providerId) throws AgentTrustException {
        httpClient.delete("/api/v1/federation/providers/" + providerId);
    }

    /**
     * Verifies a federated OIDC token.
     *
     * @param token       the federated token to verify
     * @param issuerHint  optional issuer URL to skip discovery (may be {@code null})
     * @return the verification result
     * @throws AgentTrustException if the request fails
     */
    public VerifyTokenResult verifyToken(String token, String issuerHint) throws AgentTrustException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("token", token);
        if (issuerHint != null) body.put("issuer_hint", issuerHint);
        Map<String, Object> result = httpClient.post("/api/v1/federation/tokens/verify", body);
        return VerifyTokenResult.fromJson(result);
    }

    /**
     * Initializes an AgentTrust session from a verified federated token.
     *
     * @param token      the federated token
     * @param issuerHint optional issuer URL (may be {@code null})
     * @return the session
     * @throws AgentTrustException if the request fails
     */
    public Session initSession(String token, String issuerHint) throws AgentTrustException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("token", token);
        if (issuerHint != null) body.put("issuer_hint", issuerHint);
        Map<String, Object> result = httpClient.post("/api/v1/federation/sessions/init", body);
        return Session.fromMap(result);
    }

    /**
     * Issues an opaque federation token for the given agent.
     *
     * @param agentId  the agent identifier
     * @param audience optional intended audience for the token (may be {@code null})
     * @param nonce    optional nonce (may be {@code null})
     * @param ttl      optional TTL in seconds (may be {@code null} for default)
     * @return the issued ID token result
     * @throws AgentTrustException if the request fails
     */
    public IssueIDTokenResult issueIDToken(String agentId, String audience, String nonce,
                                           Integer ttl) throws AgentTrustException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("agent_id", agentId);
        if (audience != null) body.put("audience", audience);
        if (ttl != null) body.put("ttl", ttl);
        Map<String, Object> result = httpClient.post(
                "/api/v1/federation/tokens/issue", body);
        return IssueIDTokenResult.fromJson(result);
    }

    /**
     * Result returned by {@link FederationAPI#verifyToken(String, String)}.
     */
    public static class VerifyTokenResult {
        private final boolean valid;
        private final String agentId;
        private final String issuer;
        private final String expiresAt;
        private final String error;

        public VerifyTokenResult(boolean valid, String agentId, String issuer,
                                 String expiresAt, String error) {
            this.valid = valid;
            this.agentId = agentId;
            this.issuer = issuer;
            this.expiresAt = expiresAt;
            this.error = error;
        }

        /** @return whether the token is valid */
        public boolean isValid() { return valid; }

        /** @return the agent identifier the token represents, or {@code null} */
        public String getAgentId() { return agentId; }

        /** @return the issuer URL, or {@code null} */
        public String getIssuer() { return issuer; }

        /** @return when the token expires (ISO 8601 string), or {@code null} */
        public String getExpiresAt() { return expiresAt; }

        /** @return error message if verification failed, or {@code null} */
        public String getError() { return error; }

        /** @param data parsed JSON
         *  @return the parsed result */
        public static VerifyTokenResult fromJson(Map<String, Object> data) {
            if (data == null) return null;
            String agentId = JsonUtil.getString(data, "agent_id");
            if (agentId == null) agentId = JsonUtil.getString(data, "agentId");
            String expiresAt = JsonUtil.getString(data, "expires_at");
            if (expiresAt == null) expiresAt = JsonUtil.getString(data, "expiresAt");
            return new VerifyTokenResult(
                    JsonUtil.getBoolean(data, "valid", false),
                    agentId,
                    JsonUtil.getString(data, "issuer"),
                    expiresAt,
                    JsonUtil.getString(data, "error")
            );
        }
    }

    /**
     * Result returned by {@link FederationAPI#issueIDToken(String, String, String, Integer)}.
     */
    public static class IssueIDTokenResult {
        private final String idToken;
        private final int expiresIn;

        public IssueIDTokenResult(String idToken, int expiresIn) {
            this.idToken = idToken;
            this.expiresIn = expiresIn;
        }

        /** @return the issued ID token (JWT) */
        public String getIdToken() { return idToken; }

        /** @return seconds until the token expires */
        public int getExpiresIn() { return expiresIn; }

        /** @param data parsed JSON
         *  @return the parsed result */
        public static IssueIDTokenResult fromJson(Map<String, Object> data) {
            if (data == null) return null;
            String idToken = JsonUtil.getString(data, "id_token");
            if (idToken == null) idToken = JsonUtil.getString(data, "idToken");
            if (idToken == null) idToken = JsonUtil.getString(data, "token");
            int expiresIn = JsonUtil.getInt(data, "expires_in", 0);
            if (expiresIn == 0) expiresIn = JsonUtil.getInt(data, "expiresIn", 0);
            return new IssueIDTokenResult(idToken, expiresIn);
        }
    }
}
