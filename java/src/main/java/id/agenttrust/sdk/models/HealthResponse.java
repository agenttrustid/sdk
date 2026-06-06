package id.agenttrust.sdk.models;

import id.agenttrust.sdk.JsonUtil;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Contains the result of a health check.
 */
public class HealthResponse {

    private final String status;
    private final String service;
    private final String version;

    public HealthResponse(String status, String service, String version) {
        this.status = status;
        this.service = service;
        this.version = version;
    }

    /** Service health status ("healthy", "degraded", "unhealthy"). */
    public String getStatus() {
        return status;
    }

    /** Name of the service responding. */
    public String getService() {
        return service;
    }

    /** Service version. */
    public String getVersion() {
        return version;
    }

    /** Creates a {@code HealthResponse} from a parsed JSON map. */
    public static HealthResponse fromJson(Map<String, Object> data) {
        if (data == null) {
            return null;
        }
        return new HealthResponse(
                JsonUtil.getString(data, "status", ""),
                JsonUtil.getString(data, "service", ""),
                JsonUtil.getString(data, "version", "")
        );
    }

    /** Serializes this response to a JSON-compatible map. */
    public Map<String, Object> toJson() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("status", status);
        map.put("service", service);
        map.put("version", version);
        return map;
    }

    @Override
    public String toString() {
        return "HealthResponse{status='" + status + "', service='" + service +
                "', version='" + version + "'}";
    }
}
