//! Approval management for elevated actions.
//!
//! When an action check returns `elevation_required: true`, an approval request
//! is created. Use this API to approve, deny, or query the status of such
//! requests.
//!
//! # Example
//!
//! ```rust,no_run
//! use agenttrustid::AgentTrustClient;
//!
//! let client = AgentTrustClient::builder().build().unwrap();
//!
//! // Approve an elevated action
//! client.approvals().approve("approval-123", "admin@example.com").unwrap();
//!
//! // Check approval status
//! let status = client.approvals().get("approval-123").unwrap();
//! println!("Status: {}", status.status);
//! ```

use serde::Serialize;

use crate::client::AgentTrustClient;
use crate::error::Result;
use crate::models::ApprovalRequestStatus;

/// Request body for approve/deny operations.
#[derive(Debug, Serialize)]
struct ApprovalDecisionRequest {
    decided_by: String,
}

/// Provides approval management for elevated actions.
///
/// Obtained via [`AgentTrustClient::approvals()`].
pub struct ApprovalsAPI<'a> {
    pub(crate) client: &'a AgentTrustClient,
}

impl<'a> ApprovalsAPI<'a> {
    /// Approve an elevated action request.
    ///
    /// # Arguments
    ///
    /// * `approval_id` - The approval request identifier.
    /// * `decided_by` - Identity of the person or system approving the action.
    ///
    /// # Errors
    ///
    /// Returns an error if the approval request is not found or already decided.
    pub fn approve(&self, approval_id: &str, decided_by: &str) -> Result<()> {
        let path = format!("/mcp/approvals/{}/approve", approval_id);
        let req = ApprovalDecisionRequest {
            decided_by: decided_by.to_string(),
        };
        self.client.request_no_response("POST", &path, Some(&req))
    }

    /// Deny an elevated action request.
    ///
    /// # Arguments
    ///
    /// * `approval_id` - The approval request identifier.
    /// * `decided_by` - Identity of the person or system denying the action.
    ///
    /// # Errors
    ///
    /// Returns an error if the approval request is not found or already decided.
    pub fn deny(&self, approval_id: &str, decided_by: &str) -> Result<()> {
        let path = format!("/mcp/approvals/{}/deny", approval_id);
        let req = ApprovalDecisionRequest {
            decided_by: decided_by.to_string(),
        };
        self.client.request_no_response("POST", &path, Some(&req))
    }

    /// Get the current status of an approval request.
    ///
    /// # Arguments
    ///
    /// * `approval_id` - The approval request identifier.
    ///
    /// # Errors
    ///
    /// Returns [`AgentTrustError::NotFound`] if the approval request does not exist.
    pub fn get(&self, approval_id: &str) -> Result<ApprovalRequestStatus> {
        let path = format!("/mcp/approvals/{}", approval_id);
        self.client.request("GET", &path, None::<&()>)
    }
}
