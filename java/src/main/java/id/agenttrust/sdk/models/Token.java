package id.agenttrust.sdk.models;

import id.agenttrust.sdk.JsonUtil;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents an opaque agent token issued by ATI.
 *
 * <p>Tokens are random strings prefixed with {@code at_} (e.g.
 * {@code at_xK3z9...}). They are <strong>not</strong> JWTs — they have no
 * signature and cannot be validated client-side. To check a token, call
 * {@link id.agenttrust.sdk.TokensAPI#introspect(id.agenttrust.sdk.TokensAPI.IntrospectTokenRequest)}.
 */
public class Token {

    private final String token;
    private final String agentId;
    private final List<String> scopes;
    private final List<String> audience;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private final String tokenId;

    public Token(String token, String agentId, List<String> scopes, List<String> audience,
                 Instant issuedAt, Instant expiresAt, String tokenId) {
        this.token = token;
        this.agentId = agentId;
        this.scopes = scopes != null ? Collections.unmodifiableList(new ArrayList<>(scopes)) : Collections.emptyList();
        this.audience = audience != null ? Collections.unmodifiableList(new ArrayList<>(audience)) : Collections.emptyList();
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.tokenId = tokenId;
    }

    /** The opaque token string (prefix {@code at_}) for use in Authorization headers. */
    public String getToken() {
        return token;
    }

    /** The agent this token was issued to. */
    public String getAgentId() {
        return agentId;
    }

    /** Permissions granted by this token. */
    public List<String> getScopes() {
        return scopes;
    }

    /** Intended recipients/resources for this token. */
    public List<String> getAudience() {
        return audience;
    }

    /** When the token was issued. */
    public Instant getIssuedAt() {
        return issuedAt;
    }

    /** When the token expires. */
    public Instant getExpiresAt() {
        return expiresAt;
    }

    /** Unique token identifier. */
    public String getTokenId() {
        return tokenId;
    }

    /** Returns {@code true} if the token has expired. */
    public boolean isExpired() {
        if (expiresAt == null) {
            return false;
        }
        return Instant.now().isAfter(expiresAt);
    }

    /** Returns the number of seconds until this token expires, or 0 if already expired. */
    public long ttlSeconds() {
        if (expiresAt == null) {
            return 0;
        }
        long seconds = Duration.between(Instant.now(), expiresAt).getSeconds();
        return Math.max(0, seconds);
    }

    /**
     * Creates a {@code Token} from a parsed JSON map.
     * <p>
     * Handles alternative field names: {@code token}/{@code agent_token} for
     * the token string, {@code scopes}/{@code scope} for the scope list, and
     * {@code token_id}/{@code id} for the token identifier.
     */
    public static Token fromJson(Map<String, Object> data) {
        if (data == null) {
            return null;
        }

        String tok = JsonUtil.getString(data, "token");
        if (tok == null || tok.isEmpty()) {
            tok = JsonUtil.getString(data, "agent_token", "");
        }

        List<String> scopes = JsonUtil.getStringList(data, "scopes");
        if (scopes.isEmpty()) {
            scopes = JsonUtil.getStringList(data, "scope");
        }

        String tokenId = JsonUtil.getString(data, "token_id");
        if (tokenId == null || tokenId.isEmpty()) {
            tokenId = JsonUtil.getString(data, "id");
        }

        return new Token(
                tok,
                JsonUtil.getString(data, "agent_id", ""),
                scopes,
                JsonUtil.getStringList(data, "audience"),
                JsonUtil.parseInstant(JsonUtil.getString(data, "issued_at")),
                JsonUtil.parseInstant(JsonUtil.getString(data, "expires_at")),
                tokenId
        );
    }

    /** Serializes this token to a JSON-compatible map. */
    public Map<String, Object> toJson() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("token", token);
        map.put("agent_id", agentId);
        map.put("scopes", new ArrayList<Object>(scopes));
        map.put("audience", new ArrayList<Object>(audience));
        if (issuedAt != null) {
            map.put("issued_at", issuedAt.toString());
        }
        if (expiresAt != null) {
            map.put("expires_at", expiresAt.toString());
        }
        if (tokenId != null) {
            map.put("token_id", tokenId);
        }
        return map;
    }

    @Override
    public String toString() {
        return "Token{agentId='" + agentId + "', scopes=" + scopes + ", tokenId='" + tokenId + "'}";
    }
}
