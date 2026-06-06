//! Agent registration and lifecycle management.
//!
//! Agents are the core identity primitive in ATI. Each agent gets an Ed25519
//! registration data upon creation.
//!
//! # Example
//!
//! ```rust,no_run
//! use agenttrustid::{AgentTrustClient, CreateAgentRequest};
//!
//! let client = AgentTrustClient::builder()
//!     .base_url("http://localhost:8080")
//!     .api_key("sk_live_xxx")
//!     .build()
//!     .unwrap();
//!
//! let agent = client.agents().create(&CreateAgentRequest {
//!     name: "my-assistant".to_string(),
//!     framework: "langchain".to_string(),
//!     capabilities: vec!["files:read".to_string(), "web:fetch".to_string()],
//!     ..Default::default()
//! }).unwrap();
//!
//! // Save agent.private_key securely!
//! println!("Agent ID: {}", agent.id);
//! ```

use crate::client::AgentTrustClient;
use crate::error::Result;
use crate::models::{
    Agent, AgentListResponse, CreateAgentRequest, CreateAgentResponse, RevokeAgentRequest,
};

/// Provides agent registration and lifecycle management.
///
/// Obtained via [`AgentTrustClient::agents()`].
pub struct AgentsAPI<'a> {
    pub(crate) client: &'a AgentTrustClient,
}

impl<'a> AgentsAPI<'a> {
    /// Register a new agent with the AgentTrust ID identity service.
    ///
    /// The returned [`Agent`] includes a `private_key` that is **only available
    /// during creation**. Store it securely; it cannot be retrieved again.
    ///
    /// # Errors
    ///
    /// - [`AgentTrustError::Validation`](crate::AgentTrustError::Validation) if required fields are missing.
    /// - [`AgentTrustError::Authentication`](crate::AgentTrustError::Authentication) if the API key is invalid.
    pub fn create(&self, req: &CreateAgentRequest) -> Result<Agent> {
        let resp: CreateAgentResponse = self.client.request("POST", "/api/v1/agents", Some(req))?;
        Ok(resp.into_agent())
    }

    /// Retrieve an agent by its unique ID.
    ///
    /// # Errors
    ///
    /// - [`AgentTrustError::NotFound`](crate::AgentTrustError::NotFound) if the agent does not exist.
    pub fn get(&self, agent_id: &str) -> Result<Agent> {
        let path = format!("/api/v1/agents/{}", agent_id);
        let resp: Agent = self.client.request("GET", &path, None::<&()>)?;
        Ok(resp)
    }

    /// List all agents, optionally filtered by organization ID.
    ///
    /// Pass `None` for `org_id` to list agents across all organizations.
    pub fn list(&self, org_id: Option<&str>) -> Result<Vec<Agent>> {
        let path = match org_id {
            Some(id) => format!("/api/v1/agents?org_id={}", id),
            None => "/api/v1/agents".to_string(),
        };
        let resp: AgentListResponse = self.client.request("GET", &path, None::<&()>)?;
        let agents = resp.agents.into_iter().map(|ad| ad.into_agent()).collect();
        Ok(agents)
    }

    /// Permanently revoke an agent and all its tokens.
    ///
    /// This action is immediate and cannot be undone.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The agent to revoke.
    /// * `reason` - Human-readable reason for the revocation.
    pub fn revoke(&self, agent_id: &str, reason: &str) -> Result<()> {
        let path = format!("/api/v1/agents/{}/revoke", agent_id);
        let body = RevokeAgentRequest {
            reason: reason.to_string(),
        };
        self.client.request_no_response("POST", &path, Some(&body))
    }
}

// Implement Default for CreateAgentRequest so users can use ..Default::default()
impl Default for CreateAgentRequest {
    fn default() -> Self {
        Self {
            name: String::new(),
            framework: "custom".to_string(),
            capabilities: Vec::new(),
            metadata: serde_json::Value::Object(serde_json::Map::new()),
            org_id: None,
        }
    }
}
