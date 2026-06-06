//! MCP session management.
//!
//! Use this API to initialize and query MCP sessions that track agent-server
//! interactions, call counts, and scope ceilings.
//!
//! # Example
//!
//! ```rust,no_run
//! use agenttrustid::AgentTrustClient;
//!
//! let client = AgentTrustClient::builder().build().unwrap();
//!
//! let session = client.sessions().init_session("agent-123", "mcp-server-1").unwrap();
//! println!("Session: {}", session.session_id);
//!
//! let fetched = client.sessions().get_session(&session.session_id).unwrap();
//! println!("Mode: {}", fetched.mode);
//! ```

use crate::client::AgentTrustClient;
use crate::error::Result;
use crate::models::{InitSessionRequest, Session};

/// Provides MCP session management operations.
///
/// Obtained via [`AgentTrustClient::sessions()`].
pub struct SessionsAPI<'a> {
    pub(crate) client: &'a AgentTrustClient,
}

impl<'a> SessionsAPI<'a> {
    /// Initialize a new MCP session for an agent connecting to a server.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The agent initiating the session.
    /// * `server_id` - The MCP server to connect to.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails (network, auth, validation, etc.).
    pub fn init_session(&self, agent_id: &str, server_id: &str) -> Result<Session> {
        let req = InitSessionRequest {
            agent_id: agent_id.to_string(),
            server_id: server_id.to_string(),
        };
        self.client
            .request("POST", "/mcp/sessions/init", Some(&req))
    }

    /// Retrieve an existing session by its ID.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The unique session identifier.
    ///
    /// # Errors
    ///
    /// Returns [`AgentTrustError::NotFound`] if the session does not exist.
    pub fn get_session(&self, session_id: &str) -> Result<Session> {
        let path = format!("/mcp/sessions/{}", session_id);
        self.client.request("GET", &path, None::<&()>)
    }
}
