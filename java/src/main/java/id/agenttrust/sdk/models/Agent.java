package id.agenttrust.sdk.models;

import id.agenttrust.sdk.JsonUtil;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents a registered AI agent in the AgentTrust ID system.
 *
 * <p>The platform does not issue certificates; use
 * {@link id.agenttrust.sdk.TokensAPI#issue} to mint opaque {@code at_} tokens for
 * an agent.
 */
public class Agent {

    private final String id;
    private final String name;
    private final String orgId;
    private final String framework;
    private final String publicKey;
    private final String status;
    private final List<String> capabilities;
    private final Map<String, Object> metadata;
    private final Instant createdAt;
    private final String privateKey;

    public Agent(String id, String name, String orgId, String framework, String publicKey,
                 String status, List<String> capabilities, Map<String, Object> metadata,
                 Instant createdAt, String privateKey) {
        this.id = id;
        this.name = name;
        this.orgId = orgId;
        this.framework = framework != null ? framework : "custom";
        this.publicKey = publicKey;
        this.status = status != null ? status : "active";
        this.capabilities = capabilities != null ? Collections.unmodifiableList(new ArrayList<>(capabilities)) : Collections.emptyList();
        this.metadata = metadata != null ? Collections.unmodifiableMap(new LinkedHashMap<>(metadata)) : Collections.emptyMap();
        this.createdAt = createdAt;
        this.privateKey = privateKey;
    }

    /**
     * Returns a copy of this agent carrying the given private key. Used when the
     * SDK generates the keypair client-side: the private key stays local and is
     * attached to the returned agent rather than round-tripped through the API.
     */
    public Agent withPrivateKey(String privateKeyPem) {
        return new Agent(id, name, orgId, framework, publicKey, status,
                capabilities, metadata, createdAt, privateKeyPem);
    }

    /** Unique agent identifier. */
    public String getId() {
        return id;
    }

    /** Human-readable agent name, unique within an organization. */
    public String getName() {
        return name;
    }

    /** Organization that owns this agent. */
    public String getOrgId() {
        return orgId;
    }

    /** AI framework used (e.g. "openai", "langchain", "custom"). */
    public String getFramework() {
        return framework;
    }

    /** Agent's Ed25519 public key (PEM-encoded). */
    public String getPublicKey() {
        return publicKey;
    }

    /** Agent status ("active", "suspended", "revoked"). */
    public String getStatus() {
        return status;
    }

    /** Permissions the agent can request (e.g. "files:read"). */
    public List<String> getCapabilities() {
        return capabilities;
    }

    /** Arbitrary key-value metadata associated with the agent. */
    public Map<String, Object> getMetadata() {
        return metadata;
    }

    /** When the agent was registered. */
    public Instant getCreatedAt() {
        return createdAt;
    }

    /**
     * Agent's private key. Only populated when the platform supplies one
     * during agent creation; store it securely as it cannot be retrieved
     * again.
     */
    public String getPrivateKey() {
        return privateKey;
    }

    /**
     * Creates an {@code Agent} from a parsed JSON map.
     * <p>
     * Handles the nested response format {@code {"agent": {...}}} returned by
     * the create endpoint, as well as flat agent objects.
     */
    @SuppressWarnings("unchecked")
    public static Agent fromJson(Map<String, Object> data) {
        if (data == null) {
            return null;
        }

        Map<String, Object> agentData = data;
        if (data.containsKey("agent") && data.get("agent") instanceof Map) {
            agentData = new LinkedHashMap<>((Map<String, Object>) data.get("agent"));
        }

        Map<String, Object> meta = JsonUtil.getMap(agentData, "metadata");

        return new Agent(
                JsonUtil.getString(agentData, "id", ""),
                JsonUtil.getString(agentData, "name", ""),
                JsonUtil.getString(agentData, "org_id", ""),
                JsonUtil.getString(agentData, "framework", "custom"),
                JsonUtil.getString(agentData, "public_key", ""),
                JsonUtil.getString(agentData, "status", "active"),
                JsonUtil.getStringList(agentData, "capabilities"),
                meta != null ? meta : new LinkedHashMap<>(),
                JsonUtil.parseInstant(JsonUtil.getString(agentData, "created_at")),
                JsonUtil.getString(agentData, "private_key")
        );
    }

    /** Serializes this agent to a JSON-compatible map. */
    public Map<String, Object> toJson() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", id);
        map.put("name", name);
        map.put("org_id", orgId);
        map.put("framework", framework);
        map.put("public_key", publicKey);
        map.put("status", status);
        map.put("capabilities", new ArrayList<Object>(capabilities));
        map.put("metadata", new LinkedHashMap<>(metadata));
        if (createdAt != null) {
            map.put("created_at", createdAt.toString());
        }
        if (privateKey != null) {
            map.put("private_key", privateKey);
        }
        return map;
    }

    @Override
    public String toString() {
        return "Agent{id='" + id + "', name='" + name + "', status='" + status + "'}";
    }
}
