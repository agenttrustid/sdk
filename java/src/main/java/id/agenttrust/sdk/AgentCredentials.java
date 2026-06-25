package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Manages an agent's runtime authentication: auto-issues a WIMSE token via the
 * proof-of-possession flow, caches it, refreshes it before expiry, and produces
 * per-request {@code Authorization: Bearer} + {@code DPoP} headers. The private
 * key never leaves the {@link AgentKeys.KeyStore} — both the PoP signature (at
 * issuance) and the DPoP proof (per request) are signed through it.
 *
 * <p>Build it from a client, then route runtime checks through it:
 *
 * <pre>{@code
 * AgentCredentials creds = new AgentCredentials(client, keyStore, agentId, publicKeyPem);
 * client.useAgentCredentials(creds);
 * client.actions().check(ActionsAPI.ActionCheckRequest.builder()
 *         .agentId(agentId).toolName("read_file").build());
 * }</pre>
 *
 * <p>Thread-safe.
 */
public final class AgentCredentials {

    /** How long before expiry the manager proactively re-issues (milliseconds). */
    private static final long REFRESH_SKEW_MILLIS = 60_000L;

    private final WIMSEAPI wimse;
    private final String baseUrl;
    private final AgentKeys.KeyStore keyStore;
    private final String agentId;
    private final String publicKeyPem;
    private final List<String> audience;
    private final Integer ttlSeconds;

    private final Object lock = new Object();
    private String token = "";
    private long expiresAtMillis = 0L;

    public AgentCredentials(
            AgentTrustClient client, AgentKeys.KeyStore keyStore, String agentId, String publicKeyPem) {
        this(client, keyStore, agentId, publicKeyPem, null, null);
    }

    public AgentCredentials(
            AgentTrustClient client,
            AgentKeys.KeyStore keyStore,
            String agentId,
            String publicKeyPem,
            List<String> audience,
            Integer ttlSeconds) {
        this.wimse = client.wimse();
        this.baseUrl = client.getBaseUrl();
        this.keyStore = keyStore;
        this.agentId = agentId;
        this.publicKeyPem = publicKeyPem;
        this.audience = audience;
        this.ttlSeconds = ttlSeconds;
    }

    /**
     * Returns a currently-valid WIMSE token, issuing or refreshing one via the
     * proof-of-possession flow when the cache is empty or near expiry.
     *
     * @return the cached or freshly-issued token
     * @throws AgentTrustException if issuance fails
     */
    public String token() throws AgentTrustException {
        synchronized (lock) {
            if (!token.isEmpty() && (expiresAtMillis - System.currentTimeMillis()) > REFRESH_SKEW_MILLIS) {
                return token;
            }
            WIMSEAPI.IssueWIMSETokenRequest.Builder req =
                    WIMSEAPI.IssueWIMSETokenRequest.builder().agentId(agentId);
            if (audience != null) {
                req.audience(audience);
            }
            if (ttlSeconds != null) {
                req.ttlSeconds(ttlSeconds);
            }
            WIMSEAPI.WIMSETokenResponse resp = wimse.issueTokenWithProof(req.build(), keyStore);
            token = resp.getToken();
            expiresAtMillis = parseExpiry(resp.getExpiresAt());
            return token;
        }
    }

    /**
     * Returns the headers to attach to a runtime request for the given method and
     * request path: a Bearer WIMSE token plus a fresh DPoP proof bound to the
     * request (htu = base URL + path) and the token (ath).
     *
     * @param method the HTTP method of the request
     * @param path   the request path
     * @return an ordered map of headers to attach
     * @throws AgentTrustException if token issuance fails
     */
    public Map<String, String> runtimeHeaders(String method, String path) throws AgentTrustException {
        String t = token();
        String proof = DPoP.mintDpopProofWithKeyStore(keyStore, agentId, publicKeyPem, method, baseUrl + path, t);
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", "Bearer " + t);
        headers.put("DPoP", proof);
        return headers;
    }

    /** Clears the cached token, forcing a fresh issuance on the next call. */
    public void invalidate() {
        synchronized (lock) {
            token = "";
            expiresAtMillis = 0L;
        }
    }

    /**
     * Parses an ISO-8601 expiry to epoch millis; on failure falls back to a
     * conservative short window so the manager re-issues soon.
     */
    private static long parseExpiry(String s) {
        if (s != null && !s.isEmpty()) {
            try {
                return Instant.parse(s).toEpochMilli();
            } catch (RuntimeException ignored) {
                // fall through to the conservative default
            }
        }
        return System.currentTimeMillis() + 300_000L;
    }
}
