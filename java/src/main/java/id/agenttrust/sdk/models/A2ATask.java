package id.agenttrust.sdk.models;

import id.agenttrust.sdk.JsonUtil;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents an A2A task.
 * <p>
 * Supports both the legacy task shape (flat {@code status} string with
 * {@code source_agent_id}/{@code target_agent_id}) and the A2A v1.0 Task shape
 * ({@code id}, {@code contextId}, structured {@code status{state,timestamp}},
 * {@code history}, {@code artifacts}). Parsing is tolerant of either form.
 */
public class A2ATask {

    private final String id;
    private final String contextId;
    private final String sourceAgentId;
    private final String targetAgentId;
    private final String status;
    private final TaskStatus statusObject;
    private final Map<String, Object> message;
    private final List<Object> history;
    private final List<Object> artifacts;
    private final Map<String, Object> metadata;
    private final String createdAt;
    private final String updatedAt;

    public A2ATask(String id, String contextId, String sourceAgentId, String targetAgentId,
                   String status, TaskStatus statusObject,
                   Map<String, Object> message, List<Object> history, List<Object> artifacts,
                   Map<String, Object> metadata, String createdAt, String updatedAt) {
        this.id = id;
        this.contextId = contextId;
        this.sourceAgentId = sourceAgentId;
        this.targetAgentId = targetAgentId;
        this.status = status;
        this.statusObject = statusObject;
        this.message = message;
        this.history = history;
        this.artifacts = artifacts;
        this.metadata = metadata;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    /** @return the task identifier */
    public String getId() { return id; }

    /** @return the A2A v1.0 context identifier, or {@code null} */
    public String getContextId() { return contextId; }

    /** @return the agent that initiated the task, or {@code null} (legacy shape) */
    public String getSourceAgentId() { return sourceAgentId; }

    /** @return the agent that should perform the task, or {@code null} (legacy shape) */
    public String getTargetAgentId() { return targetAgentId; }

    /**
     * @return the task status as a string. For v1.0 tasks this is the
     *         {@code status.state} value; for legacy tasks it is the flat
     *         {@code status} field. May be {@code null}.
     */
    public String getStatus() { return status; }

    /** @return the structured v1.0 status object, or {@code null} for legacy tasks */
    public TaskStatus getStatusObject() { return statusObject; }

    /** @return the request message payload, or {@code null} */
    public Map<String, Object> getMessage() { return message; }

    /** @return the message history (v1.0), or {@code null} */
    public List<Object> getHistory() { return history; }

    /** @return artifacts produced by the task, or {@code null} */
    public List<Object> getArtifacts() { return artifacts; }

    /** @return arbitrary metadata associated with the task, or {@code null} */
    public Map<String, Object> getMetadata() { return metadata; }

    /** @return when the task was created (ISO 8601 string), or {@code null} */
    public String getCreatedAt() { return createdAt; }

    /** @return when the task was last updated (ISO 8601 string), or {@code null} */
    public String getUpdatedAt() { return updatedAt; }

    /**
     * Parses a task from a JSON map, tolerating both legacy and v1.0 shapes.
     *
     * @param data parsed JSON object
     * @return the parsed task, or {@code null} if {@code data} is {@code null}
     */
    @SuppressWarnings("unchecked")
    public static A2ATask fromJson(Map<String, Object> data) {
        if (data == null) {
            return null;
        }

        String contextId = JsonUtil.getString(data, "contextId");
        if (contextId == null) {
            contextId = JsonUtil.getString(data, "context_id");
        }

        String sourceAgentId = JsonUtil.getString(data, "source_agent_id");
        if (sourceAgentId == null) {
            sourceAgentId = JsonUtil.getString(data, "sourceAgentId");
        }
        String targetAgentId = JsonUtil.getString(data, "target_agent_id");
        if (targetAgentId == null) {
            targetAgentId = JsonUtil.getString(data, "targetAgentId");
        }
        String createdAt = JsonUtil.getString(data, "created_at");
        if (createdAt == null) {
            createdAt = JsonUtil.getString(data, "createdAt");
        }
        String updatedAt = JsonUtil.getString(data, "updated_at");
        if (updatedAt == null) {
            updatedAt = JsonUtil.getString(data, "updatedAt");
        }

        // status may be a flat string (legacy) or an object {state,timestamp} (v1.0)
        TaskStatus statusObject = null;
        String statusString;
        Object rawStatus = data.get("status");
        if (rawStatus instanceof Map) {
            statusObject = TaskStatus.fromJson((Map<String, Object>) rawStatus);
            statusString = statusObject.getState();
        } else {
            statusString = JsonUtil.getString(data, "status");
        }

        Map<String, Object> message = JsonUtil.getMap(data, "message");
        Map<String, Object> metadata = JsonUtil.getMap(data, "metadata");

        Object historyObj = data.get("history");
        List<Object> history = historyObj instanceof List ? (List<Object>) historyObj : null;

        Object artifactsObj = data.get("artifacts");
        List<Object> artifacts = artifactsObj instanceof List ? (List<Object>) artifactsObj : null;

        return new A2ATask(
                JsonUtil.getString(data, "id"),
                contextId,
                sourceAgentId,
                targetAgentId,
                statusString,
                statusObject,
                message,
                history,
                artifacts,
                metadata,
                createdAt,
                updatedAt
        );
    }

    /** @return mutable map representation suitable for JSON serialization */
    public Map<String, Object> toJson() {
        Map<String, Object> map = new LinkedHashMap<>();
        if (id != null) map.put("id", id);
        if (contextId != null) map.put("contextId", contextId);
        if (sourceAgentId != null) map.put("source_agent_id", sourceAgentId);
        if (targetAgentId != null) map.put("target_agent_id", targetAgentId);
        if (statusObject != null) {
            map.put("status", statusObject.toJson());
        } else if (status != null) {
            map.put("status", status);
        }
        if (message != null) map.put("message", message);
        if (history != null) map.put("history", history);
        if (artifacts != null) map.put("artifacts", artifacts);
        if (metadata != null) map.put("metadata", metadata);
        if (createdAt != null) map.put("created_at", createdAt);
        if (updatedAt != null) map.put("updated_at", updatedAt);
        return map;
    }

    @Override
    public String toString() {
        return "A2ATask{id='" + id + "', status='" + status + "'}";
    }

    /** The structured status of an A2A v1.0 task. */
    public static class TaskStatus {
        private final String state;
        private final String timestamp;
        private final Map<String, Object> message;

        public TaskStatus(String state, String timestamp, Map<String, Object> message) {
            this.state = state;
            this.timestamp = timestamp;
            this.message = message != null
                    ? Collections.unmodifiableMap(new LinkedHashMap<>(message))
                    : null;
        }

        /** @return the task state (e.g. {@code "submitted"}, {@code "working"}, {@code "completed"}) */
        public String getState() { return state; }

        /** @return the status timestamp (ISO 8601 string), or {@code null} */
        public String getTimestamp() { return timestamp; }

        /** @return the status message payload, or {@code null} */
        public Map<String, Object> getMessage() { return message; }

        public static TaskStatus fromJson(Map<String, Object> data) {
            if (data == null) {
                return new TaskStatus(null, null, null);
            }
            return new TaskStatus(
                    JsonUtil.getString(data, "state"),
                    JsonUtil.getString(data, "timestamp"),
                    JsonUtil.getMap(data, "message")
            );
        }

        Map<String, Object> toJson() {
            Map<String, Object> map = new LinkedHashMap<>();
            if (state != null) map.put("state", state);
            if (timestamp != null) map.put("timestamp", timestamp);
            if (message != null) map.put("message", message);
            return map;
        }
    }
}
