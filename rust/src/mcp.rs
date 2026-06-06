//! MCP server registry and proxy operations.
//!
//! Use this API to register MCP (Model Context Protocol) servers with AgentTrust ID so
//! the gateway can mediate tool calls and apply Guardian policy.
//!
//! # Example
//!
//! ```rust,no_run
//! use agenttrustid::{AgentTrustClient, RegisterMCPServerRequest};
//!
//! let client = AgentTrustClient::builder().build().unwrap();
//!
//! let server = client.mcp().register_server(&RegisterMCPServerRequest {
//!     name: "filesystem".to_string(),
//!     url: "https://mcp.example.com/fs".to_string(),
//!     capabilities: Some(vec!["files:read".to_string()]),
//! }).unwrap();
//!
//! println!("Registered server: {}", server.id);
//! ```

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::AgentTrustClient;
use crate::error::Result;
use crate::models::{MCPServer, RegisterMCPServerRequest};

/// Provides MCP server registry and proxy operations.
///
/// Obtained via [`AgentTrustClient::mcp()`].
pub struct Mcp<'a> {
    pub(crate) client: &'a AgentTrustClient,
}

#[derive(Debug, Deserialize)]
struct McpServerListResponse {
    #[serde(default)]
    servers: Option<Vec<MCPServer>>,
}

#[derive(Debug, Serialize)]
struct McpRpcRequest<'a> {
    jsonrpc: &'a str,
    id: u64,
    method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<&'a Value>,
}

impl<'a> Mcp<'a> {
    /// List all registered MCP servers.
    ///
    /// Calls `GET /mcp/servers`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let servers = client.mcp().list_servers().unwrap();
    /// for s in servers {
    ///     println!("{}: {}", s.name, s.url);
    /// }
    /// ```
    pub fn list_servers(&self) -> Result<Vec<MCPServer>> {
        let value: Value = self.client.request("GET", "/mcp/servers", None::<&()>)?;
        if let Value::Array(_) = &value {
            let servers: Vec<MCPServer> = serde_json::from_value(value)?;
            return Ok(servers);
        }
        let resp: McpServerListResponse = serde_json::from_value(value)?;
        Ok(resp.servers.unwrap_or_default())
    }

    /// Retrieve a registered MCP server by ID.
    ///
    /// Calls `GET /mcp/servers/{id}`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let s = client.mcp().get_server("srv-1").unwrap();
    /// println!("server name: {}", s.name);
    /// ```
    pub fn get_server(&self, server_id: &str) -> Result<MCPServer> {
        let path = format!("/mcp/servers/{}", server_id);
        self.client.request("GET", &path, None::<&()>)
    }

    /// Register a new MCP server with ATI.
    ///
    /// Calls `POST /mcp/servers`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::{AgentTrustClient, RegisterMCPServerRequest};
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let s = client.mcp().register_server(&RegisterMCPServerRequest {
    ///     name: "fs".into(),
    ///     url: "https://mcp.example.com".into(),
    ///     capabilities: None,
    /// }).unwrap();
    /// assert!(!s.id.is_empty());
    /// ```
    pub fn register_server(&self, req: &RegisterMCPServerRequest) -> Result<MCPServer> {
        self.client.request("POST", "/mcp/servers", Some(req))
    }

    /// Remove a registered MCP server.
    ///
    /// Calls `DELETE /mcp/servers/{id}`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// client.mcp().remove_server("srv-1").unwrap();
    /// ```
    pub fn remove_server(&self, server_id: &str) -> Result<()> {
        let path = format!("/mcp/servers/{}", server_id);
        self.client
            .request_no_response("DELETE", &path, None::<&()>)
    }

    /// Call an MCP tool through the AgentTrust ID proxy.
    ///
    /// Calls `POST /mcp/{server_id}` with a JSON-RPC 2.0 envelope. Returns the
    /// `result` field on success.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # use serde_json::json;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let result = client.mcp().call_tool(
    ///     "srv-1",
    ///     "tools/call",
    ///     Some(json!({"name": "ls"})),
    /// ).unwrap();
    /// println!("{}", result);
    /// ```
    pub fn call_tool(&self, server_id: &str, method: &str, params: Option<Value>) -> Result<Value> {
        let path = format!("/mcp/{}", server_id);
        let req = McpRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method,
            params: params.as_ref(),
        };
        let resp: Value = self.client.request("POST", &path, Some(req))?;
        if let Some(result) = resp.get("result") {
            return Ok(result.clone());
        }
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AgentTrustError;
    use mockito::Server;

    #[test]
    fn test_list_servers_success() {
        let mut srv = Server::new();
        let mock = srv
            .mock("GET", "/mcp/servers")
            .with_status(200)
            .with_body(r#"{"servers":[{"id":"s1","name":"fs","url":"https://example/fs"}]}"#)
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let servers = client.mcp().list_servers().unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].id, "s1");
        mock.assert();
    }

    #[test]
    fn test_get_server_not_found() {
        let mut srv = Server::new();
        let mock = srv
            .mock("GET", "/mcp/servers/missing")
            .with_status(404)
            .with_body(r#"{"message":"server not found"}"#)
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let err = client.mcp().get_server("missing").unwrap_err();
        assert!(matches!(err, AgentTrustError::NotFound { .. }));
        mock.assert();
    }

    #[test]
    fn test_register_server_validation_error() {
        let mut srv = Server::new();
        let mock = srv
            .mock("POST", "/mcp/servers")
            .with_status(400)
            .with_body(r#"{"message":"name required"}"#)
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let err = client
            .mcp()
            .register_server(&RegisterMCPServerRequest {
                name: String::new(),
                url: "https://x".to_string(),
                capabilities: None,
            })
            .unwrap_err();
        assert!(matches!(err, AgentTrustError::Validation { .. }));
        mock.assert();
    }

    #[test]
    fn test_remove_server_server_error() {
        let mut srv = Server::new();
        let mock = srv
            .mock("DELETE", "/mcp/servers/s1")
            .with_status(500)
            .with_body(r#"{"message":"boom"}"#)
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let err = client.mcp().remove_server("s1").unwrap_err();
        match err {
            AgentTrustError::Api { status, .. } => assert_eq!(status, 500),
            other => panic!("unexpected: {:?}", other),
        }
        mock.assert();
    }
}
