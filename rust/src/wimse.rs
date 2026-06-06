//! WIMSE workload identity tokens.
//!
//! WIMSE is the IETF working group for workload identity. AgentTrust ID exposes a thin
//! wrapper that issues SPIFFE-style workload identity tokens for registered
//! agents and verifies them.
//!
//! # Example
//!
//! ```rust,no_run
//! use agenttrustid::{AgentTrustClient, IssueWIMSETokenRequest, VerifyWIMSETokenRequest};
//!
//! let client = AgentTrustClient::builder().build().unwrap();
//!
//! let issued = client.wimse().issue_token(&IssueWIMSETokenRequest {
//!     agent_id: "agent-1".to_string(),
//!     service_name: Some("payments".to_string()),
//!     environment: Some("prod".to_string()),
//!     ttl_seconds: Some(900),
//! }).unwrap();
//!
//! let verified = client.wimse().verify_wimse(&VerifyWIMSETokenRequest {
//!     token: issued.token.clone(),
//!     trust_domain_filter: None,
//! }).unwrap();
//!
//! assert!(verified.valid);
//! ```

use crate::client::AgentTrustClient;
use crate::error::Result;
use crate::models::{
    IssueWIMSETokenRequest, VerifyWIMSETokenRequest, VerifyWIMSETokenResponse, WIMSETokenResponse,
};

/// Provides WIMSE workload identity token operations.
///
/// Obtained via [`AgentTrustClient::wimse()`].
pub struct Wimse<'a> {
    pub(crate) client: &'a AgentTrustClient,
}

impl<'a> Wimse<'a> {
    /// Issue a WIMSE workload identity token.
    ///
    /// Calls `POST /api/v1/wimse/token`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::{AgentTrustClient, IssueWIMSETokenRequest};
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let issued = client.wimse().issue_token(&IssueWIMSETokenRequest {
    ///     agent_id: "agent-1".into(),
    ///     service_name: None,
    ///     environment: None,
    ///     ttl_seconds: None,
    /// }).unwrap();
    /// println!("workload {}", issued.workload_id);
    /// ```
    pub fn issue_token(&self, req: &IssueWIMSETokenRequest) -> Result<WIMSETokenResponse> {
        self.client
            .request("POST", "/api/v1/wimse/token", Some(req))
    }

    /// Build the JWT-signed headers expected by a downstream service.
    ///
    /// Returns the headers to attach to outbound requests:
    ///
    /// - `Authorization: Bearer <token>`
    /// - `X-WIMSE-Workload-ID: <workload_id>`
    /// - `X-WIMSE-Trust-Domain: <trust_domain>`
    ///
    /// This is a convenience wrapper around [`Wimse::issue_token`].
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::{AgentTrustClient, IssueWIMSETokenRequest};
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let headers = client.wimse().get_jwt_signed_headers(&IssueWIMSETokenRequest {
    ///     agent_id: "agent-1".into(),
    ///     service_name: None,
    ///     environment: None,
    ///     ttl_seconds: None,
    /// }).unwrap();
    /// for (k, v) in &headers {
    ///     println!("{}: {}", k, v);
    /// }
    /// ```
    pub fn get_jwt_signed_headers(
        &self,
        req: &IssueWIMSETokenRequest,
    ) -> Result<Vec<(String, String)>> {
        let resp = self.issue_token(req)?;
        Ok(vec![
            (
                "Authorization".to_string(),
                format!("Bearer {}", resp.token),
            ),
            ("X-WIMSE-Workload-ID".to_string(), resp.workload_id),
            ("X-WIMSE-Trust-Domain".to_string(), resp.trust_domain),
        ])
    }

    /// Verify a WIMSE workload identity token.
    ///
    /// Calls `POST /api/v1/wimse/verify`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::{AgentTrustClient, VerifyWIMSETokenRequest};
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let v = client.wimse().verify_wimse(&VerifyWIMSETokenRequest {
    ///     token: "eyJ...".into(),
    ///     trust_domain_filter: None,
    /// }).unwrap();
    /// println!("valid: {}", v.valid);
    /// ```
    pub fn verify_wimse(&self, req: &VerifyWIMSETokenRequest) -> Result<VerifyWIMSETokenResponse> {
        self.client
            .request("POST", "/api/v1/wimse/verify", Some(req))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AgentTrustError;
    use mockito::Server;

    #[test]
    fn test_issue_token_success() {
        let mut srv = Server::new();
        let mock = srv
            .mock("POST", "/api/v1/wimse/token")
            .with_status(200)
            .with_body(
                r#"{
                    "token":"eyJ-abc",
                    "workload_id":"spiffe://ati/agent-1",
                    "trust_domain":"ati",
                    "expires_at":"2026-01-01T00:00:00Z"
                }"#,
            )
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let resp = client
            .wimse()
            .issue_token(&IssueWIMSETokenRequest {
                agent_id: "agent-1".into(),
                service_name: None,
                environment: None,
                ttl_seconds: None,
            })
            .unwrap();
        assert_eq!(resp.token, "eyJ-abc");
        assert_eq!(resp.workload_id, "spiffe://ati/agent-1");
        mock.assert();
    }

    #[test]
    fn test_get_jwt_signed_headers_success() {
        let mut srv = Server::new();
        let mock = srv
            .mock("POST", "/api/v1/wimse/token")
            .with_status(200)
            .with_body(
                r#"{"token":"eyJ","workload_id":"spiffe://x","trust_domain":"ati","expires_at":"2026-01-01T00:00:00Z"}"#,
            )
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let headers = client
            .wimse()
            .get_jwt_signed_headers(&IssueWIMSETokenRequest {
                agent_id: "agent-1".into(),
                service_name: None,
                environment: None,
                ttl_seconds: None,
            })
            .unwrap();
        let auth = headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert_eq!(auth, "Bearer eyJ");
        mock.assert();
    }

    #[test]
    fn test_verify_wimse_validation_error() {
        let mut srv = Server::new();
        let mock = srv
            .mock("POST", "/api/v1/wimse/verify")
            .with_status(400)
            .with_body(r#"{"message":"missing token"}"#)
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let err = client
            .wimse()
            .verify_wimse(&VerifyWIMSETokenRequest {
                token: String::new(),
                trust_domain_filter: None,
            })
            .unwrap_err();
        assert!(matches!(err, AgentTrustError::Validation { .. }));
        mock.assert();
    }

    #[test]
    fn test_issue_token_server_error() {
        let mut srv = Server::new();
        let mock = srv
            .mock("POST", "/api/v1/wimse/token")
            .with_status(500)
            .with_body(r#"{"message":"server"}"#)
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let err = client
            .wimse()
            .issue_token(&IssueWIMSETokenRequest {
                agent_id: "x".into(),
                service_name: None,
                environment: None,
                ttl_seconds: None,
            })
            .unwrap_err();
        match err {
            AgentTrustError::Api { status, .. } => assert_eq!(status, 500),
            other => panic!("unexpected: {:?}", other),
        }
        mock.assert();
    }
}
