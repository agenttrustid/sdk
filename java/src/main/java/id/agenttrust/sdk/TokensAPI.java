package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.models.IntrospectionResult;
import id.agenttrust.sdk.models.Token;
import id.agenttrust.sdk.models.VerificationResult;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Opaque agent token issuance, introspection, and revocation.
 *
 * <p>Tokens are random opaque strings prefixed {@code at_} — not JWTs. They
 * have no signature and cannot be validated client-side. To check a token,
 * call {@link #introspect(IntrospectTokenRequest)}.
 *
 * <p>Obtain an instance via {@link AgentTrustClient#tokens()}.
 */
public class TokensAPI {

    private final AgentTrustHttpClient httpClient;

    TokensAPI(AgentTrustHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Issues a new opaque agent token (prefix {@code at_}).
     *
     * @param request the token issuance parameters
     * @return the issued token; use {@link Token#getToken()} for the
     *         {@code at_...} string to put in {@code Authorization} headers.
     * @throws AgentTrustException if the request fails
     */
    public Token issue(IssueTokenRequest request) throws AgentTrustException {
        Map<String, Object> body = request.toJson();
        Map<String, Object> result = httpClient.post("/api/v1/agent-tokens/issue", body);
        return Token.fromJson(result);
    }

    /**
     * Introspects an opaque agent token by calling
     * {@code POST /api/v1/agent-tokens/introspect}.
     *
     * @param request the introspection parameters
     * @return the introspection result {@code {active, agent_id, ...}}
     * @throws AgentTrustException if the request fails
     */
    public IntrospectionResult introspect(IntrospectTokenRequest request) throws AgentTrustException {
        Map<String, Object> body = request.toJson();
        Map<String, Object> result = httpClient.post("/api/v1/agent-tokens/introspect", body);
        return IntrospectionResult.fromJson(result);
    }

    /**
     * @deprecated Use {@link #introspect(IntrospectTokenRequest)}.
     */
    @Deprecated
    public VerificationResult verify(VerifyTokenRequest request) throws AgentTrustException {
        Map<String, Object> body = request.toJson();
        Map<String, Object> result = httpClient.post("/api/v1/agent-tokens/introspect", body);
        return VerificationResult.fromJson(result);
    }

    /**
     * Revokes a specific opaque agent token immediately.
     *
     * @param token  the opaque token string ({@code at_...}) to revoke
     * @param reason reason for revocation
     * @throws AgentTrustException if the request fails
     */
    public void revoke(String token, String reason) throws AgentTrustException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("token", token);
        body.put("reason", reason != null ? reason : "manual_revocation");
        httpClient.post("/api/v1/agent-tokens/revoke", body);
    }

    // ------------------------------------------------------------------
    // Request types
    // ------------------------------------------------------------------

    /**
     * Parameters for issuing a new capability token.
     */
    public static class IssueTokenRequest {

        private final String agentId;
        private final List<String> scope;
        private final List<String> audience;
        private final int ttl;

        private IssueTokenRequest(Builder builder) {
            this.agentId = builder.agentId;
            this.scope = builder.scope != null ? new ArrayList<>(builder.scope) : new ArrayList<>();
            this.audience = builder.audience != null ? new ArrayList<>(builder.audience) : new ArrayList<>();
            this.ttl = builder.ttl;
        }

        Map<String, Object> toJson() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("agent_id", agentId);
            map.put("scopes", new ArrayList<Object>(scope));
            map.put("ttl", ttl);
            return map;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static class Builder {
            private String agentId;
            private List<String> scope;
            private List<String> audience;
            private int ttl = 300;

            private Builder() {
            }

            public Builder agentId(String agentId) {
                this.agentId = agentId;
                return this;
            }

            public Builder scope(List<String> scope) {
                this.scope = scope;
                return this;
            }

            public Builder audience(List<String> audience) {
                this.audience = audience;
                return this;
            }

            public Builder ttl(int ttl) {
                this.ttl = ttl;
                return this;
            }

            public IssueTokenRequest build() {
                if (agentId == null || agentId.isEmpty()) {
                    throw new IllegalArgumentException("agentId is required");
                }
                return new IssueTokenRequest(this);
            }
        }
    }

    /**
     * Parameters for {@code POST /api/v1/agent-tokens/introspect}.
     */
    public static class IntrospectTokenRequest {

        private final String token;
        private final String target;
        private final List<String> requiredScopes;

        IntrospectTokenRequest(String token, String target, List<String> requiredScopes) {
            this.token = token;
            this.target = target;
            this.requiredScopes = requiredScopes != null
                    ? new ArrayList<>(requiredScopes)
                    : new ArrayList<>();
        }

        private IntrospectTokenRequest(Builder builder) {
            this(builder.token, builder.target, builder.requiredScopes);
        }

        Map<String, Object> toJson() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("token", token);
            if (target != null) {
                map.put("target", target);
            }
            map.put("required_scopes", new ArrayList<Object>(requiredScopes));
            return map;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static class Builder {
            private String token;
            private String target;
            private List<String> requiredScopes;

            private Builder() {
            }

            public Builder token(String token) {
                this.token = token;
                return this;
            }

            public Builder target(String target) {
                this.target = target;
                return this;
            }

            public Builder requiredScopes(List<String> requiredScopes) {
                this.requiredScopes = requiredScopes;
                return this;
            }

            public IntrospectTokenRequest build() {
                if (token == null || token.isEmpty()) {
                    throw new IllegalArgumentException("token is required");
                }
                return new IntrospectTokenRequest(this);
            }
        }
    }

    /**
     * @deprecated Use {@link IntrospectTokenRequest}.
     */
    @Deprecated
    public static class VerifyTokenRequest {
        private final IntrospectTokenRequest delegate;

        private VerifyTokenRequest(IntrospectTokenRequest delegate) {
            this.delegate = delegate;
        }

        Map<String, Object> toJson() {
            return delegate.toJson();
        }

        public static Builder builder() {
            return new Builder();
        }

        public static class Builder {
            private String token;
            private String target;
            private List<String> requiredScopes;

            private Builder() {
            }

            public Builder token(String token) {
                this.token = token;
                return this;
            }

            public Builder target(String target) {
                this.target = target;
                return this;
            }

            public Builder requiredScopes(List<String> requiredScopes) {
                this.requiredScopes = requiredScopes;
                return this;
            }

            public VerifyTokenRequest build() {
                if (token == null || token.isEmpty()) {
                    throw new IllegalArgumentException("token is required");
                }
                return new VerifyTokenRequest(
                        new IntrospectTokenRequest(token, target, requiredScopes)
                );
            }
        }
    }
}
