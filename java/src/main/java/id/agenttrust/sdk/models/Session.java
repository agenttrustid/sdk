package id.agenttrust.sdk.models;

import id.agenttrust.sdk.JsonUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents an MCP session in the AgentTrust ID system.
 * <p>
 * Sessions track agent activity within a server context, including
 * call counts and allowed action scopes.
 */
public class Session {

    private final String sessionId;
    private final String agentId;
    private final String orgId;
    private final String source;
    private final String serverId;
    private final String mode;
    private final List<String> allowedActions;
    private final List<String> scopeCeiling;
    private final int totalCalls;
    private final int readCalls;
    private final int writeCalls;
    private final int deniedCalls;
    private final String createdAt;
    private final String lastActivityAt;

    public Session(String sessionId, String agentId, String orgId, String source,
                   String serverId, String mode, List<String> allowedActions,
                   List<String> scopeCeiling, int totalCalls, int readCalls,
                   int writeCalls, int deniedCalls, String createdAt,
                   String lastActivityAt) {
        this.sessionId = sessionId;
        this.agentId = agentId;
        this.orgId = orgId;
        this.source = source;
        this.serverId = serverId;
        this.mode = mode;
        this.allowedActions = allowedActions != null
                ? Collections.unmodifiableList(new ArrayList<>(allowedActions))
                : Collections.emptyList();
        this.scopeCeiling = scopeCeiling != null
                ? Collections.unmodifiableList(new ArrayList<>(scopeCeiling))
                : Collections.emptyList();
        this.totalCalls = totalCalls;
        this.readCalls = readCalls;
        this.writeCalls = writeCalls;
        this.deniedCalls = deniedCalls;
        this.createdAt = createdAt;
        this.lastActivityAt = lastActivityAt;
    }

    /** Unique session identifier. */
    public String getSessionId() {
        return sessionId;
    }

    /** Agent that owns this session. */
    public String getAgentId() {
        return agentId;
    }

    /** Organization ID. */
    public String getOrgId() {
        return orgId;
    }

    /** Session source (e.g. "mcp", "sdk"). */
    public String getSource() {
        return source;
    }

    /** MCP server identifier. */
    public String getServerId() {
        return serverId;
    }

    /** Session mode (e.g. "normal", "elevated"). */
    public String getMode() {
        return mode;
    }

    /** Actions allowed in this session. */
    public List<String> getAllowedActions() {
        return allowedActions;
    }

    /** Maximum scope ceiling for this session. */
    public List<String> getScopeCeiling() {
        return scopeCeiling;
    }

    /** Total number of calls in this session. */
    public int getTotalCalls() {
        return totalCalls;
    }

    /** Number of read calls. */
    public int getReadCalls() {
        return readCalls;
    }

    /** Number of write calls. */
    public int getWriteCalls() {
        return writeCalls;
    }

    /** Number of denied calls. */
    public int getDeniedCalls() {
        return deniedCalls;
    }

    /** When the session was created. */
    public String getCreatedAt() {
        return createdAt;
    }

    /** When the session was last active. */
    public String getLastActivityAt() {
        return lastActivityAt;
    }

    /** Creates a {@code Session} from a parsed JSON map. */
    public static Session fromMap(Map<String, Object> data) {
        if (data == null) {
            return null;
        }
        return new Session(
                JsonUtil.getString(data, "session_id"),
                JsonUtil.getString(data, "agent_id"),
                JsonUtil.getString(data, "org_id"),
                JsonUtil.getString(data, "source"),
                JsonUtil.getString(data, "server_id"),
                JsonUtil.getString(data, "mode"),
                JsonUtil.getStringList(data, "allowed_actions"),
                JsonUtil.getStringList(data, "scope_ceiling"),
                JsonUtil.getInt(data, "total_calls", 0),
                JsonUtil.getInt(data, "read_calls", 0),
                JsonUtil.getInt(data, "write_calls", 0),
                JsonUtil.getInt(data, "denied_calls", 0),
                JsonUtil.getString(data, "created_at"),
                JsonUtil.getString(data, "last_activity_at")
        );
    }

    /** Serializes this session to a JSON-compatible map. */
    public Map<String, Object> toJson() {
        Map<String, Object> map = new LinkedHashMap<>();
        if (sessionId != null) map.put("session_id", sessionId);
        if (agentId != null) map.put("agent_id", agentId);
        if (orgId != null) map.put("org_id", orgId);
        if (source != null) map.put("source", source);
        if (serverId != null) map.put("server_id", serverId);
        if (mode != null) map.put("mode", mode);
        map.put("allowed_actions", new ArrayList<Object>(allowedActions));
        map.put("scope_ceiling", new ArrayList<Object>(scopeCeiling));
        map.put("total_calls", totalCalls);
        map.put("read_calls", readCalls);
        map.put("write_calls", writeCalls);
        map.put("denied_calls", deniedCalls);
        if (createdAt != null) map.put("created_at", createdAt);
        if (lastActivityAt != null) map.put("last_activity_at", lastActivityAt);
        return map;
    }

    @Override
    public String toString() {
        return "Session{sessionId='" + sessionId + "', agentId='" + agentId +
                "', mode='" + mode + "'}";
    }
}
