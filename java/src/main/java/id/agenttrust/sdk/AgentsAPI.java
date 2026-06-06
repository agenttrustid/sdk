package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.models.Agent;
import id.agenttrust.sdk.models.CreateAgentRequest;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Agent registration and lifecycle management.
 * <p>
 * Provides CRUD operations for AI agents in the AgentTrust ID system.
 * Obtain an instance via {@link AgentTrustClient#agents()}.
 */
public class AgentsAPI {

    private final AgentTrustHttpClient httpClient;

    AgentsAPI(AgentTrustHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Creates a new agent.
     *
     * @param request the agent creation parameters
     * @return the created agent
     * @throws AgentTrustException if the request fails
     */
    public Agent create(CreateAgentRequest request) throws AgentTrustException {
        Map<String, Object> body = request.toJson();
        Map<String, Object> result = httpClient.post("/api/v1/agents", body);
        return Agent.fromJson(result);
    }

    /**
     * Gets an agent by ID.
     *
     * @param agentId the agent identifier
     * @return the agent
     * @throws AgentTrustException if the agent is not found or the request fails
     */
    public Agent get(String agentId) throws AgentTrustException {
        Map<String, Object> result = httpClient.get("/api/v1/agents/" + agentId);
        return Agent.fromJson(result);
    }

    /**
     * Lists all agents, optionally filtered by organization.
     *
     * @param orgId organization ID filter, or null/empty for all agents
     * @return list of agents
     * @throws AgentTrustException if the request fails
     */
    @SuppressWarnings("unchecked")
    public List<Agent> list(String orgId) throws AgentTrustException {
        String path = "/api/v1/agents";
        if (orgId != null && !orgId.isEmpty()) {
            path += "?org_id=" + orgId;
        }
        Map<String, Object> result = httpClient.get(path);

        List<Agent> agents = new ArrayList<>();

        // Handle wrapped response: {"agents": [...]}
        Object agentsObj = result.get("agents");
        if (agentsObj instanceof List) {
            for (Object item : (List<Object>) agentsObj) {
                if (item instanceof Map) {
                    agents.add(Agent.fromJson((Map<String, Object>) item));
                }
            }
        }
        return agents;
    }

    /**
     * Lists all agents without organization filter.
     *
     * @return list of agents
     * @throws AgentTrustException if the request fails
     */
    public List<Agent> list() throws AgentTrustException {
        return list(null);
    }

    /**
     * Revokes an agent and all its tokens.
     * <p>
     * This is immediate and cannot be undone.
     *
     * @param agentId the agent to revoke
     * @param reason  reason for revocation
     * @throws AgentTrustException if the request fails
     */
    public void revoke(String agentId, String reason) throws AgentTrustException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("reason", reason != null ? reason : "manual_revocation");
        httpClient.post("/api/v1/agents/" + agentId + "/revoke", body);
    }
}
