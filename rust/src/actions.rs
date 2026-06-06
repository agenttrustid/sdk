//! Pre-flight action authorization checks.
//!
//! Use this API to check whether an agent is authorized to perform a specific
//! tool call before executing it. The Fast Guard check typically completes in
//! under 15 milliseconds.
//!
//! # Example
//!
//! ```rust,no_run
//! use agenttrustid::{AgentTrustClient, ActionCheckRequest};
//!
//! let client = AgentTrustClient::builder().build().unwrap();
//!
//! let result = client.actions().check(&ActionCheckRequest {
//!     agent_id: "agent-123".to_string(),
//!     tool_name: "web_search".to_string(),
//!     tool_input_summary: "latest AI research papers".to_string(),
//!     session_id: "session-456".to_string(),
//!     ..Default::default()
//! }).unwrap();
//!
//! if result.allowed {
//!     println!("Allowed! Executing tool...");
//! } else {
//!     println!("Denied: {}", result.reason.unwrap_or_default());
//! }
//! ```

use crate::client::AgentTrustClient;
use crate::error::Result;
use crate::models::{ActionCheckRequest, ActionCheckResult};
use serde::Serialize;

/// Maximum length for tool input summaries (for privacy).
const MAX_INPUT_SUMMARY_LEN: usize = 200;

/// Provides pre-flight action authorization checks.
///
/// Obtained via [`AgentTrustClient::actions()`].
pub struct ActionsAPI<'a> {
    pub(crate) client: &'a AgentTrustClient,
}

impl<'a> ActionsAPI<'a> {
    /// Perform a pre-flight authorization check for a tool call.
    ///
    /// The `tool_input_summary` field is automatically truncated to 200 characters
    /// for privacy protection.
    ///
    /// # Errors
    ///
    /// Returns an error if the check request itself fails (network, auth, etc.).
    /// A successful return with `allowed: false` is not an error.
    pub fn check(&self, req: &ActionCheckRequest) -> Result<ActionCheckResult> {
        // Build a copy with truncated input and default action
        let mut req_copy = req.clone();

        if req_copy.action.is_empty() {
            req_copy.action = "tool_call".to_string();
        }

        if req_copy.tool_input_summary.len() > MAX_INPUT_SUMMARY_LEN {
            req_copy.tool_input_summary =
                req_copy.tool_input_summary[..MAX_INPUT_SUMMARY_LEN].to_string();
        }

        let action_name = if req_copy.tool_name.is_empty() {
            req_copy.action.as_str()
        } else {
            req_copy.tool_name.as_str()
        };
        let body = AgentTrustActionCheckRequest {
            agent_id: req_copy.agent_id.as_str(),
            session_id: empty_as_none(req_copy.session_id.as_str()),
            action_name,
            action_effect: req_copy.action_effect.as_deref(),
            action_source: "api",
            action_input_summary: empty_as_none(req_copy.tool_input_summary.as_str()),
        };

        let resp: ActionCheckResult =
            self.client
                .request("POST", "/api/v1/agenttrust/check", Some(&body))?;
        Ok(resp)
    }
}

#[derive(Serialize)]
struct AgentTrustActionCheckRequest<'a> {
    agent_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<&'a str>,
    action_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    action_effect: Option<&'a str>,
    action_source: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    action_input_summary: Option<&'a str>,
}

fn empty_as_none(value: &str) -> Option<&str> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

// Implement Default for ActionCheckRequest so users can use ..Default::default()
impl Default for ActionCheckRequest {
    fn default() -> Self {
        Self {
            agent_id: String::new(),
            action: "tool_call".to_string(),
            tool_name: String::new(),
            tool_input_summary: String::new(),
            session_id: String::new(),
            action_effect: None,
        }
    }
}
