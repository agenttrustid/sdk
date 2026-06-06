package id.agenttrust.sdk.models;

import id.agenttrust.sdk.JsonUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents a delegation from one agent to another.
 * <p>
 * Delegations grant a subset of the source agent's scopes to a target agent
 * for a bounded period of time, with optional restrictions.
 */
public class Delegation {

    private final String id;
    private final String fromAgentId;
    private final String toAgentId;
    private final String orgId;
    private final List<String> scope;
    private final Map<String, Object> restrictions;
    private final List<String> delegationChain;
    private final String expiresAt;
    private final String revokedAt;
    private final String createdAt;

    public Delegation(String id, String fromAgentId, String toAgentId, String orgId,
                      List<String> scope, Map<String, Object> restrictions,
                      List<String> delegationChain, String expiresAt, String revokedAt,
                      String createdAt) {
        this.id = id;
        this.fromAgentId = fromAgentId;
        this.toAgentId = toAgentId;
        this.orgId = orgId;
        this.scope = scope != null
                ? Collections.unmodifiableList(new ArrayList<>(scope))
                : Collections.emptyList();
        this.restrictions = restrictions;
        this.delegationChain = delegationChain != null
                ? Collections.unmodifiableList(new ArrayList<>(delegationChain))
                : Collections.emptyList();
        this.expiresAt = expiresAt;
        this.revokedAt = revokedAt;
        this.createdAt = createdAt;
    }

    /** @return the delegation identifier */
    public String getId() { return id; }

    /** @return the agent that grants the delegation */
    public String getFromAgentId() { return fromAgentId; }

    /** @return the agent that receives the delegated capabilities */
    public String getToAgentId() { return toAgentId; }

    /** @return the organization that owns both agents */
    public String getOrgId() { return orgId; }

    /** @return the scopes granted by this delegation */
    public List<String> getScope() { return scope; }

    /** @return additional restrictions on the delegation, or {@code null} */
    public Map<String, Object> getRestrictions() { return restrictions; }

    /** @return the chain of parent delegations, if any */
    public List<String> getDelegationChain() { return delegationChain; }

    /** @return when the delegation expires (ISO 8601 string) */
    public String getExpiresAt() { return expiresAt; }

    /** @return when the delegation was revoked, or {@code null} */
    public String getRevokedAt() { return revokedAt; }

    /** @return when the delegation was created (ISO 8601 string) */
    public String getCreatedAt() { return createdAt; }

    /**
     * @param data parsed JSON object
     * @return the parsed delegation, or {@code null} if {@code data} is {@code null}
     */
    @SuppressWarnings("unchecked")
    public static Delegation fromJson(Map<String, Object> data) {
        if (data == null) {
            return null;
        }
        // The platform may wrap the response in {"delegation": {...}}.
        Map<String, Object> d = data;
        if (data.containsKey("delegation") && data.get("delegation") instanceof Map) {
            d = (Map<String, Object>) data.get("delegation");
        }

        String fromAgentId = JsonUtil.getString(d, "from_agent_id");
        if (fromAgentId == null) fromAgentId = JsonUtil.getString(d, "fromAgentId");
        String toAgentId = JsonUtil.getString(d, "to_agent_id");
        if (toAgentId == null) toAgentId = JsonUtil.getString(d, "toAgentId");
        String orgId = JsonUtil.getString(d, "org_id");
        if (orgId == null) orgId = JsonUtil.getString(d, "orgId");
        String expiresAt = JsonUtil.getString(d, "expires_at");
        if (expiresAt == null) expiresAt = JsonUtil.getString(d, "expiresAt");
        String revokedAt = JsonUtil.getString(d, "revoked_at");
        if (revokedAt == null) revokedAt = JsonUtil.getString(d, "revokedAt");
        String createdAt = JsonUtil.getString(d, "created_at");
        if (createdAt == null) createdAt = JsonUtil.getString(d, "createdAt");

        List<String> chain = JsonUtil.getStringList(d, "delegation_chain");
        if (chain.isEmpty()) {
            chain = JsonUtil.getStringList(d, "delegationChain");
        }

        return new Delegation(
                JsonUtil.getString(d, "id"),
                fromAgentId,
                toAgentId,
                orgId,
                JsonUtil.getStringList(d, "scope"),
                JsonUtil.getMap(d, "restrictions"),
                chain,
                expiresAt,
                revokedAt,
                createdAt
        );
    }

    /** @return mutable map representation suitable for JSON serialization */
    public Map<String, Object> toJson() {
        Map<String, Object> map = new LinkedHashMap<>();
        if (id != null) map.put("id", id);
        if (fromAgentId != null) map.put("from_agent_id", fromAgentId);
        if (toAgentId != null) map.put("to_agent_id", toAgentId);
        if (orgId != null) map.put("org_id", orgId);
        map.put("scope", new ArrayList<Object>(scope));
        if (restrictions != null) map.put("restrictions", restrictions);
        if (!delegationChain.isEmpty()) {
            map.put("delegation_chain", new ArrayList<Object>(delegationChain));
        }
        if (expiresAt != null) map.put("expires_at", expiresAt);
        if (revokedAt != null) map.put("revoked_at", revokedAt);
        if (createdAt != null) map.put("created_at", createdAt);
        return map;
    }

    @Override
    public String toString() {
        return "Delegation{id='" + id + "', from='" + fromAgentId +
                "', to='" + toAgentId + "'}";
    }
}
