package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.models.TelemetryEvent;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Telemetry reporting for agent behavior tracking.
 * <p>
 * Reports batches of telemetry events to the AgentTrust ID audit service.
 * Obtain an instance via {@link AgentTrustClient#telemetry()}.
 */
public class TelemetryAPI {

    private final AgentTrustHttpClient httpClient;

    TelemetryAPI(AgentTrustHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Reports a batch of telemetry events.
     *
     * @param agentId   the agent that generated the events
     * @param sessionId session ID for event correlation
     * @param events    list of telemetry events to report
     * @throws AgentTrustException if the request fails
     */
    public void report(String agentId, String sessionId, List<TelemetryEvent> events) throws AgentTrustException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("agent_id", agentId);
        body.put("session_id", sessionId);

        List<Object> eventsList = new ArrayList<>();
        for (TelemetryEvent event : events) {
            eventsList.add(event.toJson());
        }
        body.put("events", eventsList);

        httpClient.post("/api/v1/telemetry/report", body);
    }
}
