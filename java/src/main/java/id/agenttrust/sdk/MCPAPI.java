package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.models.MCPServer;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * MCP API — register, list, and proxy to MCP (Model Context Protocol) servers.
 * <p>
 * Obtain an instance via {@link AgentTrustClient#mcp()}.
 */
public class MCPAPI {

    private final AgentTrustHttpClient httpClient;

    MCPAPI(AgentTrustHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Registers a new MCP server with the platform.
     *
     * @param name         the human-readable server name
     * @param url          the server's connection URL
     * @param capabilities capabilities advertised by the server, may be {@code null}
     * @return the registered server
     * @throws AgentTrustException if the request fails
     */
    public MCPServer registerServer(String name, String url, List<String> capabilities)
            throws AgentTrustException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("name", name);
        body.put("url", url);
        if (capabilities != null) {
            body.put("capabilities", capabilities);
        }
        Map<String, Object> result = httpClient.post("/mcp/servers", body);
        return MCPServer.fromJson(result);
    }

    /**
     * Lists all registered MCP servers visible to the caller.
     *
     * @return list of MCP servers (possibly empty)
     * @throws AgentTrustException if the request fails
     */
    @SuppressWarnings("unchecked")
    public List<MCPServer> listServers() throws AgentTrustException {
        Object raw = httpClient.getRaw("/mcp/servers");
        List<Object> rawList;
        if (raw instanceof List) {
            rawList = (List<Object>) raw;
        } else if (raw instanceof Map) {
            Map<String, Object> wrapper = (Map<String, Object>) raw;
            Object servers = wrapper.get("servers");
            rawList = servers instanceof List ? (List<Object>) servers : new ArrayList<>();
        } else {
            rawList = new ArrayList<>();
        }

        List<MCPServer> result = new ArrayList<>();
        for (Object item : rawList) {
            if (item instanceof Map) {
                result.add(MCPServer.fromJson((Map<String, Object>) item));
            }
        }
        return result;
    }

    /**
     * Retrieves a specific MCP server by ID.
     *
     * @param serverId the server identifier
     * @return the server
     * @throws AgentTrustException if the server is not found or the request fails
     */
    public MCPServer getServer(String serverId) throws AgentTrustException {
        Map<String, Object> result = httpClient.get("/mcp/servers/" + serverId);
        return MCPServer.fromJson(result);
    }

    /**
     * Removes a registered MCP server.
     *
     * @param serverId the server identifier
     * @throws AgentTrustException if the request fails
     */
    public void removeServer(String serverId) throws AgentTrustException {
        httpClient.delete("/mcp/servers/" + serverId);
    }

    /**
     * Calls a tool on an MCP server via the AgentTrust ID proxy. The platform applies
     * Guardian checks to the call before forwarding it to the upstream server.
     *
     * <p>The proxy authorizes the call by agent identity, so {@code agentId} is
     * required and is sent as the {@code X-Agent-ID} header — the gateway rejects
     * the request without it.
     *
     * @param serverId  the server identifier
     * @param agentId   ID of the agent making the call; sent as the
     *                  {@code X-Agent-ID} header (required, non-empty)
     * @param method    the JSON-RPC method to invoke (e.g. {@code "tools/call"})
     * @param params    parameters for the JSON-RPC call (may be {@code null})
     * @param sessionId optional session ID; sent as the {@code X-Session-ID}
     *                  header for the duration of this call
     * @return the JSON-RPC {@code result} field, or the full response if no
     *         {@code result} is present
     * @throws IllegalArgumentException if {@code agentId} is null or empty
     * @throws AgentTrustException if the request fails
     */
    public Object callTool(String serverId, String agentId, String method, Map<String, Object> params,
                           String sessionId) throws AgentTrustException {
        if (agentId == null || agentId.isEmpty()) {
            throw new IllegalArgumentException(
                "agentId is required: the MCP proxy authorizes the call by agent identity (X-Agent-ID)");
        }
        httpClient.setHeader("X-Agent-ID", agentId);
        boolean setSession = sessionId != null && !sessionId.isEmpty();
        if (setSession) {
            httpClient.setHeader("X-Session-ID", sessionId);
        }
        try {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("jsonrpc", "2.0");
            payload.put("id", 1);
            payload.put("method", method);
            if (params != null) {
                payload.put("params", params);
            }
            Map<String, Object> response = httpClient.post("/mcp/" + serverId, payload);
            if (response != null && response.containsKey("result")) {
                return response.get("result");
            }
            return response;
        } finally {
            httpClient.removeHeader("X-Agent-ID");
            if (setSession) {
                httpClient.removeHeader("X-Session-ID");
            }
        }
    }

    /**
     * Convenience overload of {@link #callTool(String, String, String, Map, String)}
     * with no session ID.
     *
     * @param serverId server identifier
     * @param agentId  ID of the agent making the call; sent as {@code X-Agent-ID} (required)
     * @param method   JSON-RPC method
     * @param params   parameters (may be {@code null})
     * @return the JSON-RPC result
     * @throws AgentTrustException if the request fails
     */
    public Object callTool(String serverId, String agentId, String method, Map<String, Object> params)
            throws AgentTrustException {
        return callTool(serverId, agentId, method, params, null);
    }
}
