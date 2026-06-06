package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.models.AgentCard;

import java.util.Map;

/**
 * Agent Cards API — generate, retrieve, and publish A2A-compatible
 * agent cards.
 * <p>
 * Obtain an instance via {@link AgentTrustClient#agentCards()}.
 */
public class AgentCardsAPI {

    private final AgentTrustHttpClient httpClient;

    AgentCardsAPI(AgentTrustHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Generates a new agent card for the given agent.
     *
     * @param agentId the agent identifier
     * @return the freshly generated agent card
     * @throws AgentTrustException if the request fails
     */
    public AgentCard generate(String agentId) throws AgentTrustException {
        Map<String, Object> result = httpClient.post("/api/v1/agents/" + agentId + "/card");
        return AgentCard.fromJson(result);
    }

    /**
     * Retrieves the current agent card for the given agent.
     *
     * @param agentId the agent identifier
     * @return the agent card
     * @throws AgentTrustException if the agent or card is not found
     */
    public AgentCard get(String agentId) throws AgentTrustException {
        Map<String, Object> result = httpClient.get("/api/v1/agents/" + agentId + "/card");
        return AgentCard.fromJson(result);
    }

    /**
     * Publishes an agent card so that it is publicly discoverable.
     *
     * @param agentId the agent identifier
     * @return the published agent card
     * @throws AgentTrustException if the request fails
     */
    public AgentCard publish(String agentId) throws AgentTrustException {
        Map<String, Object> result = httpClient.put("/api/v1/agents/" + agentId + "/card/publish");
        return AgentCard.fromJson(result);
    }

    /**
     * Retrieves a publicly published agent card. No authentication is required
     * — this hits the well-known public discovery endpoint.
     *
     * @param agentId the agent identifier
     * @return the published agent card
     * @throws AgentTrustException if the request fails or the card is not published
     */
    public AgentCard getPublic(String agentId) throws AgentTrustException {
        Map<String, Object> result = httpClient.get("/a2a/agents/" + agentId + "/agent.json");
        return AgentCard.fromJson(result);
    }
}
