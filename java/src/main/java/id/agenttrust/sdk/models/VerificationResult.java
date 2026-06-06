package id.agenttrust.sdk.models;

import java.util.List;
import java.util.Map;

/**
 * Deprecated alias for {@link IntrospectionResult}.
 *
 * <p>The platform's verify endpoint was renamed to introspect when JWTs were
 * replaced with opaque tokens. {@code isValid()} and {@code isAuthorized()}
 * both delegate to {@link IntrospectionResult#isActive()}.
 *
 * @deprecated Use {@link IntrospectionResult}.
 */
@Deprecated
public class VerificationResult extends IntrospectionResult {

    public VerificationResult(boolean valid, boolean authorized, String agentId,
                              List<String> scopes, String reasoning, String guardTier,
                              Double confidence, Integer latencyMs) {
        super(valid && authorized, agentId, null, scopes, null, reasoning, guardTier, confidence, latencyMs);
    }

    /** @deprecated Use {@link #isActive()}. */
    @Deprecated
    public boolean isValid() {
        return isActive();
    }

    /** @deprecated Use {@link #isActive()}. */
    @Deprecated
    public boolean isAuthorized() {
        return isActive();
    }

    /** Creates a {@code VerificationResult} from a parsed JSON map. */
    public static VerificationResult fromJson(Map<String, Object> data) {
        if (data == null) {
            return null;
        }
        IntrospectionResult ir = IntrospectionResult.fromJson(data);
        return new VerificationResult(
                ir.isActive(),
                ir.isActive(),
                ir.getAgentId(),
                ir.getScopes(),
                ir.getReasoning(),
                ir.getGuardTier(),
                ir.getConfidence(),
                ir.getLatencyMs()
        );
    }
}
