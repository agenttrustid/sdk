"""AgentTrust SDK MCP (Model Context Protocol) Proxy Client"""

from typing import Dict, List, Optional

from .models import MCPServer


class MCPAPI:
    """MCP proxy client API.

    Provides a managed proxy for MCP server connections. Register MCP servers
    with AgentTrust ID and route tool calls through the proxy for security enforcement.

    Example:
        # Register an MCP server
        server = client.mcp.register_server(
            name="filesystem",
            url="http://localhost:9000",
            capabilities=["files:read", "files:write"],
        )

        # Call a tool through the proxy
        result = client.mcp.call_tool(
            server_id=server.id,
            method="tools/call",
            params={"name": "read_file", "arguments": {"path": "/tmp/data.txt"}},
        )

        # List registered servers
        servers = client.mcp.list_servers()

        # Remove a server
        client.mcp.remove_server(server.id)
    """

    def __init__(self, http_client):
        self._http = http_client

    def register_server(
        self,
        name: str,
        url: str,
        capabilities: Optional[List[str]] = None,
    ) -> MCPServer:
        """
        Register an MCP server with the AgentTrust ID proxy.

        Args:
            name: Human-readable name for the server
            url: URL where the MCP server is accessible
            capabilities: Optional list of capability strings the server provides

        Returns:
            MCPServer with the registered server details
        """
        data = {
            "name": name,
            "url": url,
        }
        if capabilities is not None:
            data["capabilities"] = capabilities

        result = self._http.post("/mcp/servers", data)
        return MCPServer.from_dict(result)

    def list_servers(self) -> List[MCPServer]:
        """
        List all registered MCP servers for the organization.

        Returns:
            List of MCPServer instances
        """
        result = self._http.get("/mcp/servers")
        servers_data = result.get("servers", result) if isinstance(result, dict) else result
        if isinstance(servers_data, list):
            return [MCPServer.from_dict(s) for s in servers_data]
        return []

    def remove_server(self, server_id: str) -> None:
        """
        Remove an MCP server registration.

        Args:
            server_id: ID of the server to remove
        """
        self._http.delete(f"/mcp/servers/{server_id}")

    def call_tool(
        self,
        server_id: str,
        method: str,
        params: Optional[Dict] = None,
        session_id: str = None,
    ) -> dict:
        """
        Call a tool on an MCP server through the AgentTrust ID proxy.

        The proxy enforces security policies before forwarding the
        JSON-RPC request to the target MCP server.

        Args:
            server_id: ID of the registered MCP server
            method: JSON-RPC method to call (e.g., "tools/call")
            params: Parameters for the method call
            session_id: AgentTrust session ID for session-scoped authorization

        Returns:
            dict with the tool call result from the MCP server
        """
        if session_id:
            self._http.headers["X-Session-ID"] = session_id
        try:
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
            }
            if params is not None:
                payload["params"] = params

            result = self._http.post(f"/mcp/{server_id}", payload)
            # JSON-RPC responses have the result nested under "result"
            if "result" in result:
                return result["result"]
            return result
        finally:
            self._http.headers.pop("X-Session-ID", None)
