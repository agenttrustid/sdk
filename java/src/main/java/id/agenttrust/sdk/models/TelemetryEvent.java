package id.agenttrust.sdk.models;

import id.agenttrust.sdk.JsonUtil;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Represents a single telemetry event for agent behavior tracking.
 */
public class TelemetryEvent {

    private final String eventType;
    private final String toolName;
    private final int durationMs;
    private final boolean success;
    private final String errorType;
    private final String timestamp;

    /**
     * Creates a new telemetry event.
     *
     * @param eventType  event type (e.g. "tool_start", "tool_end", "tool_error")
     * @param toolName   name of the tool involved
     * @param durationMs how long the operation took in milliseconds
     * @param success    whether the operation succeeded
     * @param errorType  error class name if the operation failed, or null
     * @param timestamp  ISO 8601 timestamp, or null to use the current time
     */
    public TelemetryEvent(String eventType, String toolName, int durationMs,
                          boolean success, String errorType, String timestamp) {
        this.eventType = eventType;
        this.toolName = toolName;
        this.durationMs = durationMs;
        this.success = success;
        this.errorType = errorType;
        this.timestamp = timestamp != null ? timestamp : Instant.now().toString();
    }

    /** Event type (e.g. "tool_start", "tool_end", "tool_error"). */
    public String getEventType() {
        return eventType;
    }

    /** Name of the tool involved. */
    public String getToolName() {
        return toolName;
    }

    /** How long the operation took in milliseconds. */
    public int getDurationMs() {
        return durationMs;
    }

    /** Whether the operation succeeded. */
    public boolean isSuccess() {
        return success;
    }

    /** Error class name if the operation failed. */
    public String getErrorType() {
        return errorType;
    }

    /** ISO 8601 timestamp of the event. */
    public String getTimestamp() {
        return timestamp;
    }

    /** Creates a {@code TelemetryEvent} from a parsed JSON map. */
    public static TelemetryEvent fromJson(Map<String, Object> data) {
        if (data == null) {
            return null;
        }
        return new TelemetryEvent(
                JsonUtil.getString(data, "event_type", ""),
                JsonUtil.getString(data, "tool_name", ""),
                JsonUtil.getInt(data, "duration_ms", 0),
                JsonUtil.getBoolean(data, "success", false),
                JsonUtil.getString(data, "error_type"),
                JsonUtil.getString(data, "timestamp")
        );
    }

    /** Serializes this event to a JSON-compatible map. */
    public Map<String, Object> toJson() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("event_type", eventType);
        map.put("tool_name", toolName);
        map.put("duration_ms", durationMs);
        map.put("success", success);
        if (errorType != null) {
            map.put("error_type", errorType);
        }
        map.put("timestamp", timestamp);
        return map;
    }

    @Override
    public String toString() {
        return "TelemetryEvent{eventType='" + eventType + "', toolName='" + toolName +
                "', success=" + success + "}";
    }
}
