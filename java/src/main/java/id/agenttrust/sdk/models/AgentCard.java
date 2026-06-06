package id.agenttrust.sdk.models;

import id.agenttrust.sdk.JsonUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents an A2A v1.0 Agent Card describing an agent's interfaces,
 * capabilities, skills, security, and signatures.
 * <p>
 * This model is parsed from a server-provided card. Every field is optional at
 * parse time: {@link #fromJson(Map)} never throws and defaults gracefully when
 * fields such as {@code supportedInterfaces}, {@code url}, or {@code signatures}
 * are absent, so cards from older (pre-v1.0) servers still parse cleanly.
 */
public class AgentCard {

    /** Extension URI carrying the platform-issued trust score. */
    public static final String TRUST_EXTENSION_URI = "https://agenttrust.id/ext/trust/v1";

    private final String name;
    private final String description;
    private final String version;
    private final List<SupportedInterface> supportedInterfaces;
    /** Legacy top-level {@code url} (pre-v1.0 cards), or {@code null}. */
    private final String legacyUrl;
    private final String providerOrganization;
    private final String providerUrl;
    private final Capabilities capabilities;
    private final Map<String, SecurityScheme> securitySchemes;
    private final List<Map<String, List<String>>> securityRequirements;
    private final List<String> defaultInputModes;
    private final List<String> defaultOutputModes;
    private final List<Skill> skills;
    private final List<Signature> signatures;
    private final String documentationUrl;
    private final String iconUrl;

    public AgentCard(String name, String description, String version,
                     List<SupportedInterface> supportedInterfaces, String legacyUrl,
                     String providerOrganization, String providerUrl,
                     Capabilities capabilities,
                     Map<String, SecurityScheme> securitySchemes,
                     List<Map<String, List<String>>> securityRequirements,
                     List<String> defaultInputModes, List<String> defaultOutputModes,
                     List<Skill> skills, List<Signature> signatures,
                     String documentationUrl, String iconUrl) {
        this.name = name;
        this.description = description;
        this.version = version;
        this.supportedInterfaces = unmodifiable(supportedInterfaces);
        this.legacyUrl = legacyUrl;
        this.providerOrganization = providerOrganization;
        this.providerUrl = providerUrl;
        this.capabilities = capabilities != null ? capabilities : Capabilities.empty();
        this.securitySchemes = securitySchemes != null
                ? Collections.unmodifiableMap(new LinkedHashMap<>(securitySchemes))
                : Collections.emptyMap();
        this.securityRequirements = unmodifiable(securityRequirements);
        this.defaultInputModes = unmodifiable(defaultInputModes);
        this.defaultOutputModes = unmodifiable(defaultOutputModes);
        this.skills = unmodifiable(skills);
        this.signatures = unmodifiable(signatures);
        this.documentationUrl = documentationUrl;
        this.iconUrl = iconUrl;
    }

    private static <T> List<T> unmodifiable(List<T> list) {
        return list != null
                ? Collections.unmodifiableList(new ArrayList<>(list))
                : Collections.<T>emptyList();
    }

    /** @return the agent's display name */
    public String getName() { return name; }

    /** @return the agent description, or {@code null} */
    public String getDescription() { return description; }

    /** @return the agent card version */
    public String getVersion() { return version; }

    /** @return the transport interfaces this agent supports (may be empty) */
    public List<SupportedInterface> getSupportedInterfaces() { return supportedInterfaces; }

    /** @return the legacy top-level {@code url} from a pre-v1.0 card, or {@code null} */
    public String getLegacyUrl() { return legacyUrl; }

    /** @return the provider organization name, or {@code null} */
    public String getProviderOrganization() { return providerOrganization; }

    /** @return the provider URL, or {@code null} */
    public String getProviderUrl() { return providerUrl; }

    /** @return the agent capabilities (never {@code null}) */
    public Capabilities getCapabilities() { return capabilities; }

    /** @return security schemes keyed by name (may be empty) */
    public Map<String, SecurityScheme> getSecuritySchemes() { return securitySchemes; }

    /** @return security requirements (may be empty) */
    public List<Map<String, List<String>>> getSecurityRequirements() { return securityRequirements; }

    /** @return default input modes (may be empty) */
    public List<String> getDefaultInputModes() { return defaultInputModes; }

    /** @return default output modes (may be empty) */
    public List<String> getDefaultOutputModes() { return defaultOutputModes; }

    /** @return the agent's declared skills (may be empty) */
    public List<Skill> getSkills() { return skills; }

    /** @return the agent card signatures (may be empty) */
    public List<Signature> getSignatures() { return signatures; }

    /** @return the documentation URL, or {@code null} */
    public String getDocumentationUrl() { return documentationUrl; }

    /** @return the icon URL, or {@code null} */
    public String getIconUrl() { return iconUrl; }

    /**
     * Returns the primary endpoint URL for this agent: the URL of the first
     * supported interface, falling back to a legacy top-level {@code url}.
     *
     * @return the primary URL, or {@code null} if none is declared
     */
    public String getPrimaryUrl() {
        if (!supportedInterfaces.isEmpty()) {
            String url = supportedInterfaces.get(0).getUrl();
            if (url != null) {
                return url;
            }
        }
        return legacyUrl;
    }

    /**
     * Returns the platform-issued trust score read from the trust capability
     * extension ({@code uri == "https://agenttrust.id/ext/trust/v1"}).
     *
     * @return the trust score (0-100), or {@code 0} if no trust extension is present
     */
    public int getTrustScore() {
        for (Capabilities.Extension ext : capabilities.getExtensions()) {
            if (TRUST_EXTENSION_URI.equals(ext.getUri())) {
                Integer score = JsonUtil.getInteger(ext.getParams(), "ati_trust_score");
                if (score != null) {
                    return score;
                }
            }
        }
        return 0;
    }

    /**
     * Parses an A2A v1.0 agent card from a JSON map. Tolerant of missing
     * fields: never throws and never requires a top-level {@code url}.
     *
     * @param data parsed JSON object
     * @return the agent card, or {@code null} if {@code data} is {@code null}
     */
    @SuppressWarnings("unchecked")
    public static AgentCard fromJson(Map<String, Object> data) {
        if (data == null) {
            return null;
        }

        // provider (optional)
        Map<String, Object> provider = JsonUtil.getMap(data, "provider");
        if (provider == null) provider = new LinkedHashMap<>();

        // supportedInterfaces (v1.0); we still read a legacy top-level url if present
        List<SupportedInterface> interfaces = new ArrayList<>();
        Object rawInterfaces = data.get("supportedInterfaces");
        if (rawInterfaces instanceof List) {
            for (Object item : (List<?>) rawInterfaces) {
                if (item instanceof Map) {
                    interfaces.add(SupportedInterface.fromJson((Map<String, Object>) item));
                }
            }
        }
        String legacyUrl = JsonUtil.getString(data, "url");

        // capabilities (optional)
        Capabilities capabilities = Capabilities.fromJson(JsonUtil.getMap(data, "capabilities"));

        // securitySchemes (optional)
        Map<String, SecurityScheme> securitySchemes = new LinkedHashMap<>();
        Map<String, Object> rawSchemes = JsonUtil.getMap(data, "securitySchemes");
        if (rawSchemes != null) {
            for (Map.Entry<String, Object> entry : rawSchemes.entrySet()) {
                if (entry.getValue() instanceof Map) {
                    securitySchemes.put(entry.getKey(),
                            SecurityScheme.fromJson((Map<String, Object>) entry.getValue()));
                }
            }
        }

        // securityRequirements (optional): List<Map<String, List<String>>>
        List<Map<String, List<String>>> securityRequirements = new ArrayList<>();
        Object rawReqs = data.get("securityRequirements");
        if (rawReqs instanceof List) {
            for (Object reqItem : (List<?>) rawReqs) {
                if (reqItem instanceof Map) {
                    Map<String, List<String>> req = new LinkedHashMap<>();
                    for (Map.Entry<String, Object> e : ((Map<String, Object>) reqItem).entrySet()) {
                        List<String> scopes = new ArrayList<>();
                        if (e.getValue() instanceof List) {
                            for (Object s : (List<?>) e.getValue()) {
                                scopes.add(s != null ? s.toString() : null);
                            }
                        }
                        req.put(e.getKey(), scopes);
                    }
                    securityRequirements.add(req);
                }
            }
        }

        // I/O modes (optional)
        List<String> defaultInputModes = JsonUtil.getStringList(data, "defaultInputModes");
        List<String> defaultOutputModes = JsonUtil.getStringList(data, "defaultOutputModes");

        // skills (optional)
        List<Skill> skillList = new ArrayList<>();
        Object rawSkills = data.get("skills");
        if (rawSkills instanceof List) {
            for (Object item : (List<?>) rawSkills) {
                if (item instanceof Map) {
                    skillList.add(Skill.fromJson((Map<String, Object>) item));
                }
            }
        }

        // signatures (optional)
        List<Signature> signatures = new ArrayList<>();
        Object rawSigs = data.get("signatures");
        if (rawSigs instanceof List) {
            for (Object item : (List<?>) rawSigs) {
                if (item instanceof Map) {
                    signatures.add(Signature.fromJson((Map<String, Object>) item));
                }
            }
        }

        return new AgentCard(
                JsonUtil.getString(data, "name"),
                JsonUtil.getString(data, "description"),
                JsonUtil.getString(data, "version"),
                interfaces,
                legacyUrl,
                JsonUtil.getString(provider, "organization"),
                JsonUtil.getString(provider, "url"),
                capabilities,
                securitySchemes,
                securityRequirements,
                defaultInputModes,
                defaultOutputModes,
                skillList,
                signatures,
                JsonUtil.getString(data, "documentationUrl"),
                JsonUtil.getString(data, "iconUrl")
        );
    }

    @Override
    public String toString() {
        return "AgentCard{name='" + name + "', version='" + version +
                "', trustScore=" + getTrustScore() + "}";
    }

    // -----------------------------------------------------------------------
    // Inner types
    // -----------------------------------------------------------------------

    /** A transport interface the agent is reachable on. */
    public static class SupportedInterface {
        private final String url;
        private final String protocolBinding;
        private final String protocolVersion;
        private final String tenant;

        public SupportedInterface(String url, String protocolBinding,
                                  String protocolVersion, String tenant) {
            this.url = url;
            this.protocolBinding = protocolBinding;
            this.protocolVersion = protocolVersion;
            this.tenant = tenant;
        }

        /** @return the interface URL */
        public String getUrl() { return url; }

        /** @return the protocol binding (e.g. {@code "JSONRPC"}) */
        public String getProtocolBinding() { return protocolBinding; }

        /** @return the protocol version (e.g. {@code "1.0"}) */
        public String getProtocolVersion() { return protocolVersion; }

        /** @return the tenant identifier, or {@code null} */
        public String getTenant() { return tenant; }

        public static SupportedInterface fromJson(Map<String, Object> data) {
            return new SupportedInterface(
                    JsonUtil.getString(data, "url"),
                    JsonUtil.getString(data, "protocolBinding"),
                    JsonUtil.getString(data, "protocolVersion"),
                    JsonUtil.getString(data, "tenant")
            );
        }
    }

    /** Agent capability flags and extensions. */
    public static class Capabilities {
        private final boolean streaming;
        private final boolean pushNotifications;
        private final List<Extension> extensions;
        private final Boolean extendedAgentCard;

        public Capabilities(boolean streaming, boolean pushNotifications,
                            List<Extension> extensions, Boolean extendedAgentCard) {
            this.streaming = streaming;
            this.pushNotifications = pushNotifications;
            this.extensions = extensions != null
                    ? Collections.unmodifiableList(new ArrayList<>(extensions))
                    : Collections.<Extension>emptyList();
            this.extendedAgentCard = extendedAgentCard;
        }

        static Capabilities empty() {
            return new Capabilities(false, false, null, null);
        }

        /** @return whether the agent supports streaming responses */
        public boolean isStreaming() { return streaming; }

        /** @return whether the agent supports push notifications */
        public boolean isPushNotifications() { return pushNotifications; }

        /** @return the declared capability extensions (may be empty) */
        public List<Extension> getExtensions() { return extensions; }

        /** @return whether an extended agent card is available, or {@code null} */
        public Boolean getExtendedAgentCard() { return extendedAgentCard; }

        @SuppressWarnings("unchecked")
        public static Capabilities fromJson(Map<String, Object> data) {
            if (data == null) {
                return empty();
            }
            List<Extension> extensions = new ArrayList<>();
            Object rawExt = data.get("extensions");
            if (rawExt instanceof List) {
                for (Object item : (List<?>) rawExt) {
                    if (item instanceof Map) {
                        extensions.add(Extension.fromJson((Map<String, Object>) item));
                    }
                }
            }
            Boolean extended = null;
            Object rawExtended = data.get("extendedAgentCard");
            if (rawExtended instanceof Boolean) {
                extended = (Boolean) rawExtended;
            }
            return new Capabilities(
                    JsonUtil.getBoolean(data, "streaming", false),
                    JsonUtil.getBoolean(data, "pushNotifications", false),
                    extensions,
                    extended
            );
        }

        /** A capability extension, optionally carrying parameters. */
        public static class Extension {
            private final String uri;
            private final String description;
            private final Boolean required;
            private final Map<String, Object> params;

            public Extension(String uri, String description, Boolean required,
                             Map<String, Object> params) {
                this.uri = uri;
                this.description = description;
                this.required = required;
                this.params = params != null
                        ? Collections.unmodifiableMap(new LinkedHashMap<>(params))
                        : Collections.<String, Object>emptyMap();
            }

            /** @return the extension URI */
            public String getUri() { return uri; }

            /** @return the extension description, or {@code null} */
            public String getDescription() { return description; }

            /** @return whether the extension is required, or {@code null} */
            public Boolean getRequired() { return required; }

            /** @return the extension params (never {@code null}; may be empty) */
            public Map<String, Object> getParams() { return params; }

            public static Extension fromJson(Map<String, Object> data) {
                Boolean required = null;
                Object rawRequired = data.get("required");
                if (rawRequired instanceof Boolean) {
                    required = (Boolean) rawRequired;
                }
                return new Extension(
                        JsonUtil.getString(data, "uri"),
                        JsonUtil.getString(data, "description"),
                        required,
                        JsonUtil.getMap(data, "params")
                );
            }
        }
    }

    /** A named security scheme. */
    public static class SecurityScheme {
        private final String type;
        private final String scheme;

        public SecurityScheme(String type, String scheme) {
            this.type = type;
            this.scheme = scheme;
        }

        /** @return the scheme type (e.g. {@code "http"}, {@code "oauth2"}) */
        public String getType() { return type; }

        /** @return the scheme name (e.g. {@code "bearer"}), or {@code null} */
        public String getScheme() { return scheme; }

        public static SecurityScheme fromJson(Map<String, Object> data) {
            return new SecurityScheme(
                    JsonUtil.getString(data, "type"),
                    JsonUtil.getString(data, "scheme")
            );
        }
    }

    /** A capability that an agent advertises in its agent card. */
    public static class Skill {
        private final String id;
        private final String name;
        private final String description;
        private final List<String> tags;
        private final List<String> examples;
        private final List<String> inputModes;
        private final List<String> outputModes;

        public Skill(String id, String name, String description, List<String> tags,
                     List<String> examples, List<String> inputModes, List<String> outputModes) {
            this.id = id;
            this.name = name;
            this.description = description;
            this.tags = unmodifiable(tags);
            this.examples = unmodifiable(examples);
            this.inputModes = unmodifiable(inputModes);
            this.outputModes = unmodifiable(outputModes);
        }

        /** @return the skill identifier */
        public String getId() { return id; }

        /** @return the human-readable skill name */
        public String getName() { return name; }

        /** @return the skill description, or {@code null} */
        public String getDescription() { return description; }

        /** @return the skill tags (may be empty) */
        public List<String> getTags() { return tags; }

        /** @return example invocations (may be empty) */
        public List<String> getExamples() { return examples; }

        /** @return skill-specific input modes (may be empty) */
        public List<String> getInputModes() { return inputModes; }

        /** @return skill-specific output modes (may be empty) */
        public List<String> getOutputModes() { return outputModes; }

        public static Skill fromJson(Map<String, Object> data) {
            return new Skill(
                    JsonUtil.getString(data, "id"),
                    JsonUtil.getString(data, "name"),
                    JsonUtil.getString(data, "description"),
                    JsonUtil.getStringList(data, "tags"),
                    JsonUtil.getStringList(data, "examples"),
                    JsonUtil.getStringList(data, "inputModes"),
                    JsonUtil.getStringList(data, "outputModes")
            );
        }
    }

    /** A JWS-style signature over the agent card. */
    public static class Signature {
        private final String protectedHeader;
        private final String signature;
        private final Map<String, Object> header;

        public Signature(String protectedHeader, String signature, Map<String, Object> header) {
            this.protectedHeader = protectedHeader;
            this.signature = signature;
            this.header = header != null
                    ? Collections.unmodifiableMap(new LinkedHashMap<>(header))
                    : Collections.<String, Object>emptyMap();
        }

        /** @return the protected (signed) header (base64url JWS protected header) */
        public String getProtected() { return protectedHeader; }

        /** @return the signature value */
        public String getSignature() { return signature; }

        /** @return the unprotected header (never {@code null}; may be empty) */
        public Map<String, Object> getHeader() { return header; }

        public static Signature fromJson(Map<String, Object> data) {
            return new Signature(
                    JsonUtil.getString(data, "protected"),
                    JsonUtil.getString(data, "signature"),
                    JsonUtil.getMap(data, "header")
            );
        }
    }
}
