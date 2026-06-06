package id.agenttrust.sdk.models;

import id.agenttrust.sdk.JsonUtil;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Result of {@code POST /api/v1/agent-tokens/introspect}.
 *
 * <p>The platform returns {@code {active, agent_id, org_id, scopes, expires_at}}
 * — there is no client-side validation since opaque tokens have no signature.
 */
public class IntrospectionResult {

    private final boolean active;
    private final String agentId;
    private final String orgId;
    private final List<String> scopes;
    private final Instant expiresAt;
    private final String reasoning;
    private final String guardTier;
    private final Double confidence;
    private final Integer latencyMs;

    public IntrospectionResult(boolean active, String agentId, String orgId,
                               List<String> scopes, Instant expiresAt, String reasoning,
                               String guardTier, Double confidence, Integer latencyMs) {
        this.active = active;
        this.agentId = agentId;
        this.orgId = orgId;
        this.scopes = scopes != null ? Collections.unmodifiableList(new ArrayList<>(scopes)) : Collections.emptyList();
        this.expiresAt = expiresAt;
        this.reasoning = reasoning;
        this.guardTier = guardTier;
        this.confidence = confidence;
        this.latencyMs = latencyMs;
    }

    /**
     * Whether the token is currently usable.
     *
     * @return {@code true} if the token is active
     */
    public boolean isActive() {
        return active;
    }

    /**
     * The agent that owns the token.
     *
     * @return the agent identifier
     */
    public String getAgentId() {
        return agentId;
    }

    /**
     * The organization that owns the agent.
     *
     * @return the organization identifier
     */
    public String getOrgId() {
        return orgId;
    }

    /**
     * Permissions granted by the token.
     *
     * @return immutable list of scope strings
     */
    public List<String> getScopes() {
        return scopes;
    }

    /**
     * When the token expires.
     *
     * @return token expiry timestamp, or {@code null} if not set
     */
    public Instant getExpiresAt() {
        return expiresAt;
    }

    /**
     * Human-readable explanation of the decision.
     *
     * @return reasoning string, or {@code null} if not provided
     */
    public String getReasoning() {
        return reasoning;
    }

    /**
     * Security check tier used ("fast", "spot", "deep").
     *
     * @return guard tier name, or {@code null} if not provided
     */
    public String getGuardTier() {
        return guardTier;
    }

    /**
     * Confidence score of the authorization decision (0.0 - 1.0).
     *
     * @return confidence value, or {@code null} if not provided
     */
    public Double getConfidence() {
        return confidence;
    }

    /**
     * Time taken for the check in milliseconds.
     *
     * @return latency in milliseconds, or {@code null} if not provided
     */
    public Integer getLatencyMs() {
        return latencyMs;
    }

    /**
     * Creates an {@code IntrospectionResult} from a parsed JSON map.
     *
     * @param data parsed JSON object, or {@code null}
     * @return the constructed result, or {@code null} if {@code data} is {@code null}
     */
    public static IntrospectionResult fromJson(Map<String, Object> data) {
        if (data == null) {
            return null;
        }
        // Server may use either "active" or legacy "valid"+"authorized" pair.
        boolean active;
        if (data.containsKey("active")) {
            active = JsonUtil.getBoolean(data, "active", false);
        } else {
            active = JsonUtil.getBoolean(data, "valid", false)
                    && JsonUtil.getBoolean(data, "authorized", false);
        }
        return new IntrospectionResult(
                active,
                JsonUtil.getString(data, "agent_id"),
                JsonUtil.getString(data, "org_id"),
                JsonUtil.getStringList(data, "scopes"),
                JsonUtil.parseInstant(JsonUtil.getString(data, "expires_at")),
                JsonUtil.getString(data, "reasoning"),
                JsonUtil.getString(data, "guard_tier"),
                JsonUtil.getDouble(data, "confidence"),
                JsonUtil.getInteger(data, "latency_ms")
        );
    }

    /**
     * Serializes this result to a JSON-compatible map.
     *
     * @return mutable map with snake_case keys ready for JSON serialization
     */
    public Map<String, Object> toJson() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("active", active);
        if (agentId != null) {
            map.put("agent_id", agentId);
        }
        if (orgId != null) {
            map.put("org_id", orgId);
        }
        map.put("scopes", new ArrayList<Object>(scopes));
        if (expiresAt != null) {
            map.put("expires_at", expiresAt.toString());
        }
        if (reasoning != null) {
            map.put("reasoning", reasoning);
        }
        if (guardTier != null) {
            map.put("guard_tier", guardTier);
        }
        if (confidence != null) {
            map.put("confidence", confidence);
        }
        if (latencyMs != null) {
            map.put("latency_ms", latencyMs);
        }
        return map;
    }

    @Override
    public String toString() {
        return "IntrospectionResult{active=" + active +
                ", guardTier='" + guardTier + "'}";
    }
}
