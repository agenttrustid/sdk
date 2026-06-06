package id.agenttrust.sdk.models;

import id.agenttrust.sdk.JsonUtil;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents a SIEM (Security Information and Event Management) destination
 * that audit events can be streamed to.
 */
public class SIEMDestination {

    private final String id;
    private final String orgId;
    private final String name;
    private final String destinationType;
    private final String endpointUrl;
    private final String authToken;
    private final boolean isActive;
    private final int batchSize;
    private final int flushIntervalSeconds;
    private final List<String> filterEventTypes;
    private final String createdAt;
    private final String updatedAt;

    public SIEMDestination(String id, String orgId, String name, String destinationType,
                           String endpointUrl, String authToken, boolean isActive,
                           int batchSize, int flushIntervalSeconds,
                           List<String> filterEventTypes, String createdAt,
                           String updatedAt) {
        this.id = id;
        this.orgId = orgId;
        this.name = name;
        this.destinationType = destinationType;
        this.endpointUrl = endpointUrl;
        this.authToken = authToken;
        this.isActive = isActive;
        this.batchSize = batchSize;
        this.flushIntervalSeconds = flushIntervalSeconds;
        this.filterEventTypes = filterEventTypes;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    /** @return the destination identifier */
    public String getId() { return id; }

    /** @return the organization that owns the destination */
    public String getOrgId() { return orgId; }

    /** @return the destination name */
    public String getName() { return name; }

    /** @return the destination type (e.g. "splunk", "datadog", "elastic") */
    public String getDestinationType() { return destinationType; }

    /** @return the destination endpoint URL */
    public String getEndpointUrl() { return endpointUrl; }

    /** @return the auth token used for delivery */
    public String getAuthToken() { return authToken; }

    /** @return whether the destination is currently active */
    public boolean isActive() { return isActive; }

    /** @return the batch size before flushing */
    public int getBatchSize() { return batchSize; }

    /** @return the flush interval in seconds */
    public int getFlushIntervalSeconds() { return flushIntervalSeconds; }

    /** @return event types filtered for this destination, or {@code null} for all */
    public List<String> getFilterEventTypes() { return filterEventTypes; }

    /** @return when the destination was created (ISO 8601 string) */
    public String getCreatedAt() { return createdAt; }

    /** @return when the destination was last updated (ISO 8601 string) */
    public String getUpdatedAt() { return updatedAt; }

    /**
     * @param data parsed JSON object
     * @return the parsed destination, or {@code null} if {@code data} is {@code null}
     */
    public static SIEMDestination fromJson(Map<String, Object> data) {
        if (data == null) {
            return null;
        }
        String orgId = JsonUtil.getString(data, "org_id");
        if (orgId == null) orgId = JsonUtil.getString(data, "orgId");
        String destType = JsonUtil.getString(data, "destination_type");
        if (destType == null) destType = JsonUtil.getString(data, "destinationType");
        String endpointUrl = JsonUtil.getString(data, "endpoint_url");
        if (endpointUrl == null) endpointUrl = JsonUtil.getString(data, "endpointUrl");
        String authToken = JsonUtil.getString(data, "auth_token");
        if (authToken == null) authToken = JsonUtil.getString(data, "authToken");
        String createdAt = JsonUtil.getString(data, "created_at");
        if (createdAt == null) createdAt = JsonUtil.getString(data, "createdAt");
        String updatedAt = JsonUtil.getString(data, "updated_at");
        if (updatedAt == null) updatedAt = JsonUtil.getString(data, "updatedAt");

        boolean isActive;
        if (data.containsKey("is_active")) {
            isActive = JsonUtil.getBoolean(data, "is_active", false);
        } else {
            isActive = JsonUtil.getBoolean(data, "isActive", false);
        }

        int batchSize = JsonUtil.getInt(data, "batch_size", 0);
        if (batchSize == 0) batchSize = JsonUtil.getInt(data, "batchSize", 0);
        int flushInterval = JsonUtil.getInt(data, "flush_interval_seconds", 0);
        if (flushInterval == 0) flushInterval = JsonUtil.getInt(data, "flushIntervalSeconds", 0);

        List<String> filters = JsonUtil.getStringList(data, "filter_event_types");
        if (filters.isEmpty()) {
            filters = JsonUtil.getStringList(data, "filterEventTypes");
        }

        return new SIEMDestination(
                JsonUtil.getString(data, "id"),
                orgId,
                JsonUtil.getString(data, "name"),
                destType,
                endpointUrl,
                authToken,
                isActive,
                batchSize,
                flushInterval,
                filters,
                createdAt,
                updatedAt
        );
    }

    /** @return mutable map representation suitable for JSON serialization */
    public Map<String, Object> toJson() {
        Map<String, Object> map = new LinkedHashMap<>();
        if (id != null) map.put("id", id);
        if (orgId != null) map.put("org_id", orgId);
        if (name != null) map.put("name", name);
        if (destinationType != null) map.put("destination_type", destinationType);
        if (endpointUrl != null) map.put("endpoint_url", endpointUrl);
        if (authToken != null) map.put("auth_token", authToken);
        map.put("is_active", isActive);
        map.put("batch_size", batchSize);
        map.put("flush_interval_seconds", flushIntervalSeconds);
        if (filterEventTypes != null) map.put("filter_event_types", filterEventTypes);
        if (createdAt != null) map.put("created_at", createdAt);
        if (updatedAt != null) map.put("updated_at", updatedAt);
        return map;
    }

    @Override
    public String toString() {
        return "SIEMDestination{id='" + id + "', name='" + name + "', type='" +
                destinationType + "'}";
    }
}
