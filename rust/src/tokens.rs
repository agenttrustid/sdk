//! Opaque agent token issuance, introspection, and revocation.
//!
//! Tokens are random opaque strings prefixed `at_` — not JWTs. They have no
//! signature and cannot be validated client-side. To check a token, call
//! [`TokensAPI::introspect`].
//!
//! # Example
//!
//! ```rust,no_run
//! use agenttrustid::{AgentTrustClient, IssueTokenRequest, IntrospectTokenRequest};
//!
//! let client = AgentTrustClient::builder()
//!     .base_url("http://localhost:8080")
//!     .build()
//!     .unwrap();
//!
//! // Issue a token
//! let token = client.tokens().issue(&IssueTokenRequest {
//!     agent_id: "agent-123".to_string(),
//!     scope: vec!["files:read".to_string()],
//!     audience: vec!["mcp://filesystem".to_string()],
//!     ttl: 300,
//! }).unwrap();
//!
//! // Use the opaque token in Authorization headers
//! println!("Bearer {}", token.token);
//!
//! // Introspect a token
//! let result = client.tokens().introspect(&IntrospectTokenRequest {
//!     token: token.token.clone(),
//!     target: Some("mcp://filesystem".to_string()),
//!     required_scopes: vec!["files:read".to_string()],
//! }).unwrap();
//!
//! if result.active {
//!     println!("Access granted");
//! }
//! ```

use crate::client::AgentTrustClient;
use crate::error::Result;
use crate::models::{
    IntrospectTokenRequest, IntrospectionResult, IssueTokenRequest, IssueTokenResponse,
    RevokeTokenRequest, Token,
};

/// Provides opaque agent token issuance, introspection, and revocation.
///
/// Obtained via [`AgentTrustClient::tokens()`].
pub struct TokensAPI<'a> {
    pub(crate) client: &'a AgentTrustClient,
}

impl<'a> TokensAPI<'a> {
    /// Issue a new opaque agent token (prefix `at_`) for an agent.
    ///
    /// The returned [`Token`] contains the opaque string in `Token.token` to
    /// use in `Authorization: Bearer` headers. Tokens are short-lived
    /// (default 300 seconds) and scoped to specific permissions.
    ///
    /// # Errors
    ///
    /// - [`AgentTrustError::Validation`](crate::AgentTrustError::Validation) if required fields are missing.
    /// - [`AgentTrustError::NotFound`](crate::AgentTrustError::NotFound) if the agent does not exist.
    pub fn issue(&self, req: &IssueTokenRequest) -> Result<Token> {
        let resp: IssueTokenResponse =
            self.client
                .request("POST", "/api/v1/agent-tokens/issue", Some(req))?;
        Ok(resp.into_token())
    }

    /// Introspect a token by calling `POST /api/v1/agent-tokens/introspect`.
    ///
    /// Returns `{ active, agent_id, org_id, scopes, expires_at, ... }`. The
    /// platform performs all validation server-side; opaque tokens have no
    /// signature so client-side checks aren't possible.
    ///
    /// # Errors
    ///
    /// Returns an error if the request itself fails (network, auth, etc.).
    /// A successful return with `active: false` is not an error.
    pub fn introspect(&self, req: &IntrospectTokenRequest) -> Result<IntrospectionResult> {
        let resp: IntrospectionResult =
            self.client
                .request("POST", "/api/v1/agent-tokens/introspect", Some(req))?;
        Ok(resp)
    }

    /// Deprecated alias for [`TokensAPI::introspect`].
    #[deprecated(note = "Use TokensAPI::introspect")]
    pub fn verify(&self, req: &IntrospectTokenRequest) -> Result<IntrospectionResult> {
        self.introspect(req)
    }

    /// Immediately invalidate a specific opaque agent token.
    ///
    /// # Arguments
    ///
    /// * `token` - The opaque token string (prefix `at_`) to revoke.
    /// * `reason` - Human-readable reason for the revocation.
    pub fn revoke(&self, token: &str, reason: &str) -> Result<()> {
        let body = RevokeTokenRequest {
            token: token.to_string(),
            reason: reason.to_string(),
        };
        self.client
            .request_no_response("POST", "/api/v1/agent-tokens/revoke", Some(&body))
    }
}
