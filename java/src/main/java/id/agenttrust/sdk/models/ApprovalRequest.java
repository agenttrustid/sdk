package id.agenttrust.sdk.models;

import id.agenttrust.sdk.JsonUtil;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Represents an approval request for elevated actions in the AgentTrust ID system.
 * <p>
 * When an action requires elevation, an approval request is created and
 * must be approved or denied before the action can proceed.
 */
public class ApprovalRequest {

    private final String id;
    private final String sessionId;
    private final String agentId;
    private final String orgId;
    private final String actionName;
    private final String actionEffect;
    private final String status;
    private final String createdAt;
    private final String expiresAt;
    private final String decidedBy;

    public ApprovalRequest(String id, String sessionId, String agentId, String orgId,
                           String actionName, String actionEffect, String status,
                           String createdAt, String expiresAt, String decidedBy) {
        this.id = id;
        this.sessionId = sessionId;
        this.agentId = agentId;
        this.orgId = orgId;
        this.actionName = actionName;
        this.actionEffect = actionEffect;
        this.status = status;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.decidedBy = decidedBy;
    }

    /** Unique approval request identifier. */
    public String getId() {
        return id;
    }

    /** Session that triggered the approval request. */
    public String getSessionId() {
        return sessionId;
    }

    /** Agent that requested the elevated action. */
    public String getAgentId() {
        return agentId;
    }

    /** Organization ID. */
    public String getOrgId() {
        return orgId;
    }

    /** Name of the action requiring approval. */
    public String getActionName() {
        return actionName;
    }

    /** Effect of the action (e.g. "read", "write", "admin"). */
    public String getActionEffect() {
        return actionEffect;
    }

    /** Approval status (e.g. "pending", "approved", "denied"). */
    public String getStatus() {
        return status;
    }

    /** When the approval request was created. */
    public String getCreatedAt() {
        return createdAt;
    }

    /** When the approval request expires. */
    public String getExpiresAt() {
        return expiresAt;
    }

    /** Who decided on the approval request. */
    public String getDecidedBy() {
        return decidedBy;
    }

    /** Creates an {@code ApprovalRequest} from a parsed JSON map. */
    public static ApprovalRequest fromMap(Map<String, Object> data) {
        if (data == null) {
            return null;
        }
        return new ApprovalRequest(
                JsonUtil.getString(data, "id"),
                JsonUtil.getString(data, "session_id"),
                JsonUtil.getString(data, "agent_id"),
                JsonUtil.getString(data, "org_id"),
                JsonUtil.getString(data, "action_name"),
                JsonUtil.getString(data, "action_effect"),
                JsonUtil.getString(data, "status"),
                JsonUtil.getString(data, "created_at"),
                JsonUtil.getString(data, "expires_at"),
                JsonUtil.getString(data, "decided_by")
        );
    }

    /** Serializes this approval request to a JSON-compatible map. */
    public Map<String, Object> toJson() {
        Map<String, Object> map = new LinkedHashMap<>();
        if (id != null) map.put("id", id);
        if (sessionId != null) map.put("session_id", sessionId);
        if (agentId != null) map.put("agent_id", agentId);
        if (orgId != null) map.put("org_id", orgId);
        if (actionName != null) map.put("action_name", actionName);
        if (actionEffect != null) map.put("action_effect", actionEffect);
        if (status != null) map.put("status", status);
        if (createdAt != null) map.put("created_at", createdAt);
        if (expiresAt != null) map.put("expires_at", expiresAt);
        if (decidedBy != null) map.put("decided_by", decidedBy);
        return map;
    }

    @Override
    public String toString() {
        return "ApprovalRequest{id='" + id + "', actionName='" + actionName +
                "', status='" + status + "'}";
    }
}
