package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.models.Session;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * MCP session management API.
 * <p>
 * Provides session initialization and retrieval for MCP server contexts.
 * Obtain an instance via {@link AgentTrustClient#sessions()}.
 */
public class SessionsAPI {

    private final AgentTrustHttpClient httpClient;

    SessionsAPI(AgentTrustHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Initializes a new MCP session for an agent on a server.
     *
     * @param agentId  the agent that owns the session
     * @param serverId the MCP server identifier
     * @return the initialized session
     * @throws AgentTrustException if the request fails
     */
    public Session initSession(String agentId, String serverId) throws AgentTrustException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("agent_id", agentId);
        body.put("server_id", serverId);
        Map<String, Object> result = httpClient.post("/mcp/sessions/init", body);
        return Session.fromMap(result);
    }

    /**
     * Gets an existing session by ID.
     *
     * @param sessionId the session identifier
     * @return the session
     * @throws AgentTrustException if the session is not found or the request fails
     */
    public Session getSession(String sessionId) throws AgentTrustException {
        Map<String, Object> result = httpClient.get("/mcp/sessions/" + sessionId);
        return Session.fromMap(result);
    }
}
