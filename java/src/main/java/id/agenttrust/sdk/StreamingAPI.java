package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.models.SIEMDestination;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Streaming API — manage SIEM destinations and audit-log delivery.
 * <p>
 * Mirrors the TypeScript SDK {@code StreamingAPI} class: it manages the SIEM
 * destinations the platform forwards events to. Note that this is not an
 * SSE/event-stream client — the platform pushes events to configured SIEM
 * destinations server-side.
 * <p>
 * Obtain an instance via {@link AgentTrustClient#streaming()}.
 */
public class StreamingAPI {

    private final AgentTrustHttpClient httpClient;

    StreamingAPI(AgentTrustHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Creates a new SIEM destination.
     *
     * @param request the destination parameters
     * @return the created destination
     * @throws AgentTrustException if the request fails
     */
    public SIEMDestination create(CreateDestinationRequest request) throws AgentTrustException {
        Map<String, Object> result = httpClient.post(
                "/api/v1/siem/destinations", request.toJson());
        return SIEMDestination.fromJson(result);
    }

    /**
     * Lists all SIEM destinations.
     *
     * @return list of destinations
     * @throws AgentTrustException if the request fails
     */
    @SuppressWarnings("unchecked")
    public List<SIEMDestination> list() throws AgentTrustException {
        Object raw = httpClient.getRaw("/api/v1/siem/destinations");
        List<Object> rawList;
        if (raw instanceof List) {
            rawList = (List<Object>) raw;
        } else if (raw instanceof Map) {
            Object items = ((Map<String, Object>) raw).get("destinations");
            rawList = items instanceof List ? (List<Object>) items : new ArrayList<>();
        } else {
            rawList = new ArrayList<>();
        }
        List<SIEMDestination> out = new ArrayList<>();
        for (Object item : rawList) {
            if (item instanceof Map) {
                out.add(SIEMDestination.fromJson((Map<String, Object>) item));
            }
        }
        return out;
    }

    /**
     * Retrieves a SIEM destination by ID.
     *
     * @param destinationId the destination identifier
     * @return the destination
     * @throws AgentTrustException if the destination is not found
     */
    public SIEMDestination get(String destinationId) throws AgentTrustException {
        Map<String, Object> result = httpClient.get(
                "/api/v1/siem/destinations/" + destinationId);
        return SIEMDestination.fromJson(result);
    }

    /**
     * Updates a SIEM destination.
     *
     * @param destinationId the destination identifier
     * @param request       fields to update
     * @return the updated destination
     * @throws AgentTrustException if the request fails
     */
    public SIEMDestination update(String destinationId, UpdateDestinationRequest request)
            throws AgentTrustException {
        Map<String, Object> result = httpClient.put(
                "/api/v1/siem/destinations/" + destinationId, request.toJson());
        return SIEMDestination.fromJson(result);
    }

    /**
     * Deletes a SIEM destination.
     *
     * @param destinationId the destination identifier
     * @throws AgentTrustException if the request fails
     */
    public void delete(String destinationId) throws AgentTrustException {
        httpClient.delete("/api/v1/siem/destinations/" + destinationId);
    }

    /**
     * Triggers a test delivery to a SIEM destination.
     *
     * @param destinationId the destination identifier
     * @return the raw test response
     * @throws AgentTrustException if the request fails
     */
    public Map<String, Object> test(String destinationId) throws AgentTrustException {
        return httpClient.post("/api/v1/siem/destinations/" + destinationId + "/test");
    }

    /**
     * Retrieves the recent delivery log for a destination.
     *
     * @param destinationId the destination identifier
     * @return the raw delivery log entries
     * @throws AgentTrustException if the request fails
     */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> deliveryLog(String destinationId) throws AgentTrustException {
        Object raw = httpClient.getRaw(
                "/api/v1/siem/destinations/" + destinationId + "/logs");
        List<Object> rawList;
        if (raw instanceof List) {
            rawList = (List<Object>) raw;
        } else if (raw instanceof Map) {
            Object items = ((Map<String, Object>) raw).get("logs");
            rawList = items instanceof List ? (List<Object>) items : new ArrayList<>();
        } else {
            rawList = new ArrayList<>();
        }
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object item : rawList) {
            if (item instanceof Map) {
                out.add((Map<String, Object>) item);
            }
        }
        return out;
    }

    /** Parameters for {@link StreamingAPI#create(CreateDestinationRequest)}. */
    public static class CreateDestinationRequest {
        private final String name;
        private final String destinationType;
        private final String endpointUrl;
        private final String authToken;
        private final Integer batchSize;
        private final Integer flushIntervalSeconds;
        private final List<String> filterEventTypes;

        private CreateDestinationRequest(Builder b) {
            this.name = b.name;
            this.destinationType = b.destinationType;
            this.endpointUrl = b.endpointUrl;
            this.authToken = b.authToken;
            this.batchSize = b.batchSize;
            this.flushIntervalSeconds = b.flushIntervalSeconds;
            this.filterEventTypes = b.filterEventTypes;
        }

        Map<String, Object> toJson() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("name", name);
            map.put("destination_type", destinationType);
            map.put("endpoint_url", endpointUrl);
            if (authToken != null) map.put("auth_token", authToken);
            if (batchSize != null) map.put("batch_size", batchSize);
            if (flushIntervalSeconds != null) map.put("flush_interval_seconds", flushIntervalSeconds);
            if (filterEventTypes != null) map.put("filter_event_types", filterEventTypes);
            return map;
        }

        /** @return a new builder */
        public static Builder builder() { return new Builder(); }

        /** Builder for {@link CreateDestinationRequest}. */
        public static class Builder {
            private String name;
            private String destinationType;
            private String endpointUrl;
            private String authToken;
            private Integer batchSize;
            private Integer flushIntervalSeconds;
            private List<String> filterEventTypes;

            /** @param name destination name
             *  @return this builder */
            public Builder name(String name) { this.name = name; return this; }

            /** @param type destination type (e.g. "splunk")
             *  @return this builder */
            public Builder destinationType(String type) { this.destinationType = type; return this; }

            /** @param url destination endpoint URL
             *  @return this builder */
            public Builder endpointUrl(String url) { this.endpointUrl = url; return this; }

            /** @param token auth token sent on delivery
             *  @return this builder */
            public Builder authToken(String token) { this.authToken = token; return this; }

            /** @param size batch size before flushing
             *  @return this builder */
            public Builder batchSize(int size) { this.batchSize = size; return this; }

            /** @param seconds flush interval in seconds
             *  @return this builder */
            public Builder flushIntervalSeconds(int seconds) {
                this.flushIntervalSeconds = seconds; return this;
            }

            /** @param types event types to forward (null = all)
             *  @return this builder */
            public Builder filterEventTypes(List<String> types) {
                this.filterEventTypes = types; return this;
            }

            /** @return the built request */
            public CreateDestinationRequest build() {
                if (name == null || name.isEmpty()) {
                    throw new IllegalArgumentException("name is required");
                }
                if (destinationType == null || destinationType.isEmpty()) {
                    throw new IllegalArgumentException("destinationType is required");
                }
                if (endpointUrl == null || endpointUrl.isEmpty()) {
                    throw new IllegalArgumentException("endpointUrl is required");
                }
                return new CreateDestinationRequest(this);
            }
        }
    }

    /** Parameters for {@link StreamingAPI#update(String, UpdateDestinationRequest)}. */
    public static class UpdateDestinationRequest {
        private final String name;
        private final String endpointUrl;
        private final String authToken;
        private final Boolean isActive;
        private final Integer batchSize;
        private final Integer flushIntervalSeconds;
        private final List<String> filterEventTypes;

        private UpdateDestinationRequest(Builder b) {
            this.name = b.name;
            this.endpointUrl = b.endpointUrl;
            this.authToken = b.authToken;
            this.isActive = b.isActive;
            this.batchSize = b.batchSize;
            this.flushIntervalSeconds = b.flushIntervalSeconds;
            this.filterEventTypes = b.filterEventTypes;
        }

        Map<String, Object> toJson() {
            Map<String, Object> map = new LinkedHashMap<>();
            if (name != null) map.put("name", name);
            if (endpointUrl != null) map.put("endpoint_url", endpointUrl);
            if (authToken != null) map.put("auth_token", authToken);
            if (isActive != null) map.put("is_active", isActive);
            if (batchSize != null) map.put("batch_size", batchSize);
            if (flushIntervalSeconds != null) map.put("flush_interval_seconds", flushIntervalSeconds);
            if (filterEventTypes != null) map.put("filter_event_types", filterEventTypes);
            return map;
        }

        /** @return a new builder */
        public static Builder builder() { return new Builder(); }

        /** Builder for {@link UpdateDestinationRequest}. */
        public static class Builder {
            private String name;
            private String endpointUrl;
            private String authToken;
            private Boolean isActive;
            private Integer batchSize;
            private Integer flushIntervalSeconds;
            private List<String> filterEventTypes;

            /** @param name new name @return this */
            public Builder name(String name) { this.name = name; return this; }
            /** @param url new endpoint URL @return this */
            public Builder endpointUrl(String url) { this.endpointUrl = url; return this; }
            /** @param token new auth token @return this */
            public Builder authToken(String token) { this.authToken = token; return this; }
            /** @param active enable/disable delivery @return this */
            public Builder isActive(boolean active) { this.isActive = active; return this; }
            /** @param size new batch size @return this */
            public Builder batchSize(int size) { this.batchSize = size; return this; }
            /** @param seconds new flush interval @return this */
            public Builder flushIntervalSeconds(int seconds) {
                this.flushIntervalSeconds = seconds; return this;
            }
            /** @param types event types to forward @return this */
            public Builder filterEventTypes(List<String> types) {
                this.filterEventTypes = types; return this;
            }
            /** @return the built request */
            public UpdateDestinationRequest build() {
                return new UpdateDestinationRequest(this);
            }
        }
    }
}
