package id.agenttrust.sdk.models;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Request parameters for creating a new agent.
 * <p>
 * Use the {@link Builder} for a fluent construction style:
 * <pre>{@code
 * CreateAgentRequest req = CreateAgentRequest.builder()
 *     .name("my-agent")
 *     .framework("langchain")
 *     .capabilities(List.of("files:read", "web:fetch"))
 *     .build();
 * }</pre>
 */
public class CreateAgentRequest {

    private final String name;
    private final String framework;
    private final List<String> capabilities;
    private final Map<String, Object> metadata;
    private final String orgId;
    private final String publicKey;

    private CreateAgentRequest(Builder builder) {
        this.name = builder.name;
        this.framework = builder.framework;
        this.capabilities = builder.capabilities != null
                ? Collections.unmodifiableList(new ArrayList<>(builder.capabilities))
                : Collections.emptyList();
        this.metadata = builder.metadata != null
                ? Collections.unmodifiableMap(new LinkedHashMap<>(builder.metadata))
                : Collections.emptyMap();
        this.orgId = builder.orgId;
        this.publicKey = builder.publicKey;
    }

    /** Agent name (required). */
    public String getName() {
        return name;
    }

    /** AI framework (default: "custom"). */
    public String getFramework() {
        return framework;
    }

    /** Permissions the agent can request. */
    public List<String> getCapabilities() {
        return capabilities;
    }

    /** Arbitrary key-value metadata. */
    public Map<String, Object> getMetadata() {
        return metadata;
    }

    /** Organization ID (optional; uses default org if empty). */
    public String getOrgId() {
        return orgId;
    }

    /** Optional caller-supplied Ed25519 public key (PKIX PEM). */
    public String getPublicKey() {
        return publicKey;
    }

    /** Converts this request to a JSON-compatible map for serialization. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> toJson() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("name", name);
        map.put("framework", framework != null ? framework : "custom");
        map.put("capabilities", new ArrayList<Object>(capabilities));
        map.put("metadata", new LinkedHashMap<>(metadata));
        if (orgId != null && !orgId.isEmpty()) {
            map.put("org_id", orgId);
        }
        if (publicKey != null && !publicKey.isEmpty()) {
            map.put("public_key", publicKey);
        }
        return map;
    }

    /** Creates a new builder. */
    public static Builder builder() {
        return new Builder();
    }

    /** Builder for {@link CreateAgentRequest}. */
    public static class Builder {
        private String name;
        private String framework = "custom";
        private List<String> capabilities;
        private Map<String, Object> metadata;
        private String orgId;
        private String publicKey;

        private Builder() {
        }

        /** Sets the agent name (required). */
        public Builder name(String name) {
            this.name = name;
            return this;
        }

        /** Sets the AI framework (default: "custom"). */
        public Builder framework(String framework) {
            this.framework = framework;
            return this;
        }

        /** Sets the capabilities list. */
        public Builder capabilities(List<String> capabilities) {
            this.capabilities = capabilities;
            return this;
        }

        /** Sets arbitrary metadata. */
        public Builder metadata(Map<String, Object> metadata) {
            this.metadata = metadata;
            return this;
        }

        /** Sets the organization ID. */
        public Builder orgId(String orgId) {
            this.orgId = orgId;
            return this;
        }

        /**
         * Sets a caller-supplied Ed25519 public key (PKIX PEM). When omitted, the
         * SDK generates a keypair and keeps the private key local.
         */
        public Builder publicKey(String publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        /** Builds the request. */
        public CreateAgentRequest build() {
            if (name == null || name.isEmpty()) {
                throw new IllegalArgumentException("Agent name is required");
            }
            return new CreateAgentRequest(this);
        }
    }
}
