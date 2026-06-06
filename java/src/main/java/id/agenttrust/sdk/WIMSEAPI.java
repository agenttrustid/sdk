package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * WIMSE API — workload identity token operations.
 * <p>
 * Mirrors the Go SDK {@code WIMSEAPI}: issue and verify SPIFFE-style
 * workload identity tokens for AI agents.
 * <p>
 * Obtain an instance via {@link AgentTrustClient#wimse()}.
 */
public class WIMSEAPI {

    private final AgentTrustHttpClient httpClient;

    WIMSEAPI(AgentTrustHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Issues a WIMSE workload identity token for the given agent.
     *
     * @param request the issuance parameters
     * @return the issued token
     * @throws AgentTrustException if the request fails
     */
    public WIMSETokenResponse issueToken(IssueWIMSETokenRequest request) throws AgentTrustException {
        Map<String, Object> result = httpClient.post("/api/v1/wimse/token", request.toJson());
        return WIMSETokenResponse.fromJson(result);
    }

    /**
     * Verifies a WIMSE workload identity token.
     *
     * @param token             the WIMSE token to verify
     * @param trustDomainFilter optional trust domain to require, may be {@code null}
     * @return the verification result
     * @throws AgentTrustException if the request fails
     */
    public VerifyWIMSETokenResponse verifyToken(String token, String trustDomainFilter)
            throws AgentTrustException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("token", token);
        if (trustDomainFilter != null && !trustDomainFilter.isEmpty()) {
            body.put("trust_domain_filter", trustDomainFilter);
        }
        Map<String, Object> result = httpClient.post("/api/v1/wimse/verify", body);
        return VerifyWIMSETokenResponse.fromJson(result);
    }

    /**
     * Convenience overload for {@link #verifyToken(String, String)} with no
     * trust-domain filter.
     *
     * @param token the WIMSE token to verify
     * @return the verification result
     * @throws AgentTrustException if the request fails
     */
    public VerifyWIMSETokenResponse verifyToken(String token) throws AgentTrustException {
        return verifyToken(token, null);
    }

    /** Parameters for {@link WIMSEAPI#issueToken(IssueWIMSETokenRequest)}. */
    public static class IssueWIMSETokenRequest {
        private final String agentId;
        private final String serviceName;
        private final String environment;
        private final Integer ttlSeconds;

        private IssueWIMSETokenRequest(Builder b) {
            this.agentId = b.agentId;
            this.serviceName = b.serviceName;
            this.environment = b.environment;
            this.ttlSeconds = b.ttlSeconds;
        }

        Map<String, Object> toJson() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("agent_id", agentId);
            if (serviceName != null) map.put("service_name", serviceName);
            if (environment != null) map.put("environment", environment);
            if (ttlSeconds != null) map.put("ttl_seconds", ttlSeconds);
            return map;
        }

        /** @return a new builder */
        public static Builder builder() { return new Builder(); }

        /** Builder for {@link IssueWIMSETokenRequest}. */
        public static class Builder {
            private String agentId;
            private String serviceName;
            private String environment;
            private Integer ttlSeconds;

            /** @param id agent identifier @return this */
            public Builder agentId(String id) { this.agentId = id; return this; }
            /** @param name service name @return this */
            public Builder serviceName(String name) { this.serviceName = name; return this; }
            /** @param env environment label @return this */
            public Builder environment(String env) { this.environment = env; return this; }
            /** @param ttl TTL in seconds @return this */
            public Builder ttlSeconds(int ttl) { this.ttlSeconds = ttl; return this; }
            /** @return the built request */
            public IssueWIMSETokenRequest build() {
                if (agentId == null || agentId.isEmpty()) {
                    throw new IllegalArgumentException("agentId is required");
                }
                return new IssueWIMSETokenRequest(this);
            }
        }
    }

    /** Result returned by {@link WIMSEAPI#issueToken(IssueWIMSETokenRequest)}. */
    public static class WIMSETokenResponse {
        private final String token;
        private final String workloadId;
        private final String trustDomain;
        private final String expiresAt;

        public WIMSETokenResponse(String token, String workloadId, String trustDomain,
                                  String expiresAt) {
            this.token = token;
            this.workloadId = workloadId;
            this.trustDomain = trustDomain;
            this.expiresAt = expiresAt;
        }

        /** @return the issued WIMSE token (JWT) */
        public String getToken() { return token; }

        /** @return the workload identifier (e.g. SPIFFE ID) */
        public String getWorkloadId() { return workloadId; }

        /** @return the trust domain */
        public String getTrustDomain() { return trustDomain; }

        /** @return when the token expires (ISO 8601 string) */
        public String getExpiresAt() { return expiresAt; }

        /** @param data parsed JSON
         *  @return the parsed response */
        public static WIMSETokenResponse fromJson(Map<String, Object> data) {
            if (data == null) return null;
            return new WIMSETokenResponse(
                    JsonUtil.getString(data, "token"),
                    JsonUtil.getString(data, "workload_id"),
                    JsonUtil.getString(data, "trust_domain"),
                    JsonUtil.getString(data, "expires_at")
            );
        }
    }

    /** Result returned by {@link WIMSEAPI#verifyToken(String, String)}. */
    public static class VerifyWIMSETokenResponse {
        private final boolean valid;
        private final String agentId;
        private final String workloadId;
        private final String trustDomain;
        private final List<String> capabilities;
        private final String reason;

        public VerifyWIMSETokenResponse(boolean valid, String agentId, String workloadId,
                                        String trustDomain, List<String> capabilities,
                                        String reason) {
            this.valid = valid;
            this.agentId = agentId;
            this.workloadId = workloadId;
            this.trustDomain = trustDomain;
            this.capabilities = capabilities;
            this.reason = reason;
        }

        /** @return whether the token is valid */
        public boolean isValid() { return valid; }

        /** @return the agent identifier the token represents */
        public String getAgentId() { return agentId; }

        /** @return the workload identifier */
        public String getWorkloadId() { return workloadId; }

        /** @return the trust domain */
        public String getTrustDomain() { return trustDomain; }

        /** @return capabilities granted by this token */
        public List<String> getCapabilities() { return capabilities; }

        /** @return reason for failure if invalid, otherwise {@code null} */
        public String getReason() { return reason; }

        /** @param data parsed JSON
         *  @return the parsed response */
        public static VerifyWIMSETokenResponse fromJson(Map<String, Object> data) {
            if (data == null) return null;
            return new VerifyWIMSETokenResponse(
                    JsonUtil.getBoolean(data, "valid", false),
                    JsonUtil.getString(data, "agent_id"),
                    JsonUtil.getString(data, "workload_id"),
                    JsonUtil.getString(data, "trust_domain"),
                    JsonUtil.getStringList(data, "capabilities"),
                    JsonUtil.getString(data, "reason")
            );
        }
    }
}
