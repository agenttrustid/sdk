package id.agenttrust.sdk.models;

import id.agenttrust.sdk.JsonUtil;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Contains the outcome of a pre-flight action authorization check.
 */
public class ActionCheckResult {

    private final boolean allowed;
    private final String checkId;
    private final Double confidence;
    private final String guardTier;
    private final Integer latencyMs;
    private final String reason;
    private final boolean elevationRequired;
    private final String approvalId;

    public ActionCheckResult(boolean allowed, String checkId, Double confidence,
                             String guardTier, Integer latencyMs, String reason) {
        this(allowed, checkId, confidence, guardTier, latencyMs, reason, false, null);
    }

    public ActionCheckResult(boolean allowed, String checkId, Double confidence,
                             String guardTier, Integer latencyMs, String reason,
                             boolean elevationRequired, String approvalId) {
        this.allowed = allowed;
        this.checkId = checkId;
        this.confidence = confidence;
        this.guardTier = guardTier;
        this.latencyMs = latencyMs;
        this.reason = reason;
        this.elevationRequired = elevationRequired;
        this.approvalId = approvalId;
    }

    /** Whether the action is authorized. */
    public boolean isAllowed() {
        return allowed;
    }

    /** Unique identifier for this check. */
    public String getCheckId() {
        return checkId;
    }

    /** Confidence score (0.0 - 1.0). */
    public Double getConfidence() {
        return confidence;
    }

    /** Security check tier used ("fast", "spot", "deep"). */
    public String getGuardTier() {
        return guardTier;
    }

    /** Time taken for the check in milliseconds. */
    public Integer getLatencyMs() {
        return latencyMs;
    }

    /** Human-readable explanation of the decision. */
    public String getReason() {
        return reason;
    }

    /** Whether the action requires elevated approval. */
    public boolean isElevationRequired() {
        return elevationRequired;
    }

    /** The approval request ID when elevation is required. */
    public String getApprovalId() {
        return approvalId;
    }

    /** Creates an {@code ActionCheckResult} from a parsed JSON map. */
    public static ActionCheckResult fromJson(Map<String, Object> data) {
        if (data == null) {
            return null;
        }
        return new ActionCheckResult(
                JsonUtil.getBoolean(data, "allowed", false),
                JsonUtil.getString(data, "check_id"),
                JsonUtil.getDouble(data, "confidence"),
                JsonUtil.getString(data, "guard_tier"),
                JsonUtil.getInteger(data, "latency_ms"),
                JsonUtil.getString(data, "reason"),
                JsonUtil.getBoolean(data, "elevation_required", false),
                JsonUtil.getString(data, "approval_id")
        );
    }

    /** Serializes this result to a JSON-compatible map. */
    public Map<String, Object> toJson() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("allowed", allowed);
        if (checkId != null) {
            map.put("check_id", checkId);
        }
        if (confidence != null) {
            map.put("confidence", confidence);
        }
        if (guardTier != null) {
            map.put("guard_tier", guardTier);
        }
        if (latencyMs != null) {
            map.put("latency_ms", latencyMs);
        }
        if (reason != null) {
            map.put("reason", reason);
        }
        if (elevationRequired) {
            map.put("elevation_required", true);
        }
        if (approvalId != null) {
            map.put("approval_id", approvalId);
        }
        return map;
    }

    @Override
    public String toString() {
        return "ActionCheckResult{allowed=" + allowed + ", guardTier='" + guardTier +
                "', reason='" + reason + "'}";
    }
}
