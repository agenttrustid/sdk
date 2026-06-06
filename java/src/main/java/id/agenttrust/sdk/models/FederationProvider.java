package id.agenttrust.sdk.models;

import id.agenttrust.sdk.JsonUtil;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Represents an external OIDC identity provider that has been registered
 * for federation with the AgentTrust ID platform.
 */
public class FederationProvider {

    private final String id;
    private final String orgId;
    private final String issuer;
    private final String name;
    private final String jwksUri;
    private final String authorizationEndpoint;
    private final String tokenEndpoint;
    private final String trustLevel;
    private final String status;
    private final String createdAt;
    private final String updatedAt;

    public FederationProvider(String id, String orgId, String issuer, String name,
                              String jwksUri, String authorizationEndpoint,
                              String tokenEndpoint, String trustLevel, String status,
                              String createdAt, String updatedAt) {
        this.id = id;
        this.orgId = orgId;
        this.issuer = issuer;
        this.name = name;
        this.jwksUri = jwksUri;
        this.authorizationEndpoint = authorizationEndpoint;
        this.tokenEndpoint = tokenEndpoint;
        this.trustLevel = trustLevel != null ? trustLevel : "standard";
        this.status = status != null ? status : "active";
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    /** @return the provider identifier */
    public String getId() { return id; }

    /** @return the organization that registered this provider */
    public String getOrgId() { return orgId; }

    /** @return the OIDC issuer URL */
    public String getIssuer() { return issuer; }

    /** @return the human-readable provider name */
    public String getName() { return name; }

    /** @return the JWKS endpoint URL */
    public String getJwksUri() { return jwksUri; }

    /** @return the OIDC authorization endpoint */
    public String getAuthorizationEndpoint() { return authorizationEndpoint; }

    /** @return the OIDC token endpoint */
    public String getTokenEndpoint() { return tokenEndpoint; }

    /** @return the trust level assigned to this provider */
    public String getTrustLevel() { return trustLevel; }

    /** @return the provider status (e.g. "active", "disabled") */
    public String getStatus() { return status; }

    /** @return when the provider was registered (ISO 8601 string) */
    public String getCreatedAt() { return createdAt; }

    /** @return when the provider was last updated (ISO 8601 string) */
    public String getUpdatedAt() { return updatedAt; }

    /**
     * @param data parsed JSON object
     * @return the parsed provider, or {@code null} if {@code data} is {@code null}
     */
    @SuppressWarnings("unchecked")
    public static FederationProvider fromJson(Map<String, Object> data) {
        if (data == null) {
            return null;
        }
        Map<String, Object> p = data;
        if (data.containsKey("provider") && data.get("provider") instanceof Map) {
            p = (Map<String, Object>) data.get("provider");
        }

        String orgId = JsonUtil.getString(p, "org_id");
        if (orgId == null) orgId = JsonUtil.getString(p, "orgId");
        String jwksUri = JsonUtil.getString(p, "jwks_uri");
        if (jwksUri == null) jwksUri = JsonUtil.getString(p, "jwksUri");
        String authEndpoint = JsonUtil.getString(p, "authorization_endpoint");
        if (authEndpoint == null) authEndpoint = JsonUtil.getString(p, "authorizationEndpoint");
        String tokenEndpoint = JsonUtil.getString(p, "token_endpoint");
        if (tokenEndpoint == null) tokenEndpoint = JsonUtil.getString(p, "tokenEndpoint");
        String trustLevel = JsonUtil.getString(p, "trust_level");
        if (trustLevel == null) trustLevel = JsonUtil.getString(p, "trustLevel");
        String createdAt = JsonUtil.getString(p, "created_at");
        if (createdAt == null) createdAt = JsonUtil.getString(p, "createdAt");
        String updatedAt = JsonUtil.getString(p, "updated_at");
        if (updatedAt == null) updatedAt = JsonUtil.getString(p, "updatedAt");

        return new FederationProvider(
                JsonUtil.getString(p, "id"),
                orgId,
                JsonUtil.getString(p, "issuer"),
                JsonUtil.getString(p, "name"),
                jwksUri,
                authEndpoint,
                tokenEndpoint,
                trustLevel,
                JsonUtil.getString(p, "status"),
                createdAt,
                updatedAt
        );
    }

    /** @return mutable map representation suitable for JSON serialization */
    public Map<String, Object> toJson() {
        Map<String, Object> map = new LinkedHashMap<>();
        if (id != null) map.put("id", id);
        if (orgId != null) map.put("org_id", orgId);
        if (issuer != null) map.put("issuer", issuer);
        if (name != null) map.put("name", name);
        if (jwksUri != null) map.put("jwks_uri", jwksUri);
        if (authorizationEndpoint != null) map.put("authorization_endpoint", authorizationEndpoint);
        if (tokenEndpoint != null) map.put("token_endpoint", tokenEndpoint);
        if (trustLevel != null) map.put("trust_level", trustLevel);
        if (status != null) map.put("status", status);
        if (createdAt != null) map.put("created_at", createdAt);
        if (updatedAt != null) map.put("updated_at", updatedAt);
        return map;
    }

    @Override
    public String toString() {
        return "FederationProvider{id='" + id + "', issuer='" + issuer + "'}";
    }
}
