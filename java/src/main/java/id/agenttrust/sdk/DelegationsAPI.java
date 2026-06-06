package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.models.Delegation;
import id.agenttrust.sdk.models.Session;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Delegations API — manage capability delegation between agents.
 * <p>
 * A delegation grants a subset of one agent's capabilities to another agent
 * for a bounded period of time, with optional restrictions.
 * <p>
 * Obtain an instance via {@link AgentTrustClient#delegations()}.
 */
public class DelegationsAPI {

    private final AgentTrustHttpClient httpClient;

    DelegationsAPI(AgentTrustHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Creates a new delegation.
     *
     * @param request the delegation parameters
     * @return the created delegation
     * @throws AgentTrustException if the request fails
     */
    public Delegation create(CreateDelegationRequest request) throws AgentTrustException {
        Map<String, Object> body = request.toJson();
        Map<String, Object> result = httpClient.post("/api/v1/delegations", body);
        return Delegation.fromJson(result);
    }

    /**
     * Retrieves a delegation by ID.
     *
     * @param delegationId the delegation identifier
     * @return the delegation
     * @throws AgentTrustException if the delegation is not found
     */
    public Delegation get(String delegationId) throws AgentTrustException {
        Map<String, Object> result = httpClient.get("/api/v1/delegations/" + delegationId);
        return Delegation.fromJson(result);
    }

    /**
     * Lists all delegations visible to the caller.
     *
     * @return list of delegations (possibly empty)
     * @throws AgentTrustException if the request fails
     */
    @SuppressWarnings("unchecked")
    public List<Delegation> list() throws AgentTrustException {
        Object raw = httpClient.getRaw("/api/v1/delegations");
        List<Object> rawList;
        if (raw instanceof List) {
            rawList = (List<Object>) raw;
        } else if (raw instanceof Map) {
            Map<String, Object> wrapper = (Map<String, Object>) raw;
            Object items = wrapper.get("delegations");
            rawList = items instanceof List ? (List<Object>) items : new ArrayList<>();
        } else {
            rawList = new ArrayList<>();
        }

        List<Delegation> result = new ArrayList<>();
        for (Object item : rawList) {
            if (item instanceof Map) {
                result.add(Delegation.fromJson((Map<String, Object>) item));
            }
        }
        return result;
    }

    /**
     * Revokes a delegation immediately.
     *
     * @param delegationId the delegation identifier
     * @throws AgentTrustException if the request fails
     */
    public void revoke(String delegationId) throws AgentTrustException {
        httpClient.delete("/api/v1/delegations/" + delegationId);
    }

    /**
     * Initializes an AgentTrust session backed by an existing delegation.
     *
     * @param delegationId the delegation identifier
     * @return the session
     * @throws AgentTrustException if the delegation is invalid or expired
     */
    public Session initSession(String delegationId) throws AgentTrustException {
        Map<String, Object> result = httpClient.post(
                "/api/v1/delegations/" + delegationId + "/session");
        return Session.fromMap(result);
    }

    /**
     * Parameters for {@link DelegationsAPI#create(CreateDelegationRequest)}.
     */
    public static class CreateDelegationRequest {
        private final String fromAgentId;
        private final String toAgentId;
        private final List<String> scope;
        private final Integer ttlSeconds;
        private final Map<String, Object> restrictions;
        private final String parentDelegationId;

        private CreateDelegationRequest(Builder b) {
            this.fromAgentId = b.fromAgentId;
            this.toAgentId = b.toAgentId;
            this.scope = b.scope != null ? new ArrayList<>(b.scope) : new ArrayList<>();
            this.ttlSeconds = b.ttlSeconds;
            this.restrictions = b.restrictions;
            this.parentDelegationId = b.parentDelegationId;
        }

        Map<String, Object> toJson() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("from_agent_id", fromAgentId);
            map.put("to_agent_id", toAgentId);
            map.put("scope", new ArrayList<Object>(scope));
            if (ttlSeconds != null) map.put("ttl_seconds", ttlSeconds);
            if (restrictions != null) map.put("restrictions", restrictions);
            if (parentDelegationId != null) map.put("parent_delegation_id", parentDelegationId);
            return map;
        }

        /** @return a new builder */
        public static Builder builder() { return new Builder(); }

        /** Builder for {@link CreateDelegationRequest}. */
        public static class Builder {
            private String fromAgentId;
            private String toAgentId;
            private List<String> scope;
            private Integer ttlSeconds;
            private Map<String, Object> restrictions;
            private String parentDelegationId;

            private Builder() {}

            /** @param id the agent that grants the delegation
             *  @return this builder */
            public Builder fromAgentId(String id) { this.fromAgentId = id; return this; }

            /** @param id the agent that receives the delegation
             *  @return this builder */
            public Builder toAgentId(String id) { this.toAgentId = id; return this; }

            /** @param scope the scopes to delegate
             *  @return this builder */
            public Builder scope(List<String> scope) { this.scope = scope; return this; }

            /** @param ttl the time-to-live in seconds
             *  @return this builder */
            public Builder ttlSeconds(int ttl) { this.ttlSeconds = ttl; return this; }

            /** @param restrictions arbitrary restriction predicates
             *  @return this builder */
            public Builder restrictions(Map<String, Object> restrictions) {
                this.restrictions = restrictions; return this;
            }

            /** @param parentId the parent delegation, for re-delegation chains
             *  @return this builder */
            public Builder parentDelegationId(String parentId) {
                this.parentDelegationId = parentId; return this;
            }

            /** @return the built request */
            public CreateDelegationRequest build() {
                if (fromAgentId == null || fromAgentId.isEmpty()) {
                    throw new IllegalArgumentException("fromAgentId is required");
                }
                if (toAgentId == null || toAgentId.isEmpty()) {
                    throw new IllegalArgumentException("toAgentId is required");
                }
                return new CreateDelegationRequest(this);
            }
        }
    }
}
