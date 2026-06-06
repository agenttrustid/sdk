//! Capability delegation between agents.
//!
//! Use this API to grant scoped capabilities from one agent to another, list
//! existing delegations, and revoke them.
//!
//! # Example
//!
//! ```rust,no_run
//! use agenttrustid::{AgentTrustClient, CreateDelegationRequest};
//!
//! let client = AgentTrustClient::builder().build().unwrap();
//!
//! let delegation = client.delegations().create(&CreateDelegationRequest {
//!     from_agent_id: "agent-a".to_string(),
//!     to_agent_id: "agent-b".to_string(),
//!     scope: vec!["files:read".to_string()],
//!     ttl_seconds: Some(3600),
//!     restrictions: None,
//!     parent_delegation_id: None,
//! }).unwrap();
//!
//! println!("Created delegation: {}", delegation.id);
//! ```

use serde::Deserialize;
use serde_json::Value;

use crate::client::AgentTrustClient;
use crate::error::Result;
use crate::models::{CreateDelegationRequest, Delegation, Session};

/// Provides delegation chain management.
///
/// Obtained via [`AgentTrustClient::delegations()`].
pub struct Delegations<'a> {
    pub(crate) client: &'a AgentTrustClient,
}

#[derive(Debug, Deserialize)]
struct DelegationCreateResponse {
    #[serde(default)]
    delegation: Option<Delegation>,
}

#[derive(Debug, Deserialize)]
struct DelegationListResponse {
    #[serde(default)]
    delegations: Option<Vec<Delegation>>,
}

impl<'a> Delegations<'a> {
    /// Create a new delegation.
    ///
    /// Calls `POST /api/v1/delegations`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::{AgentTrustClient, CreateDelegationRequest};
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let d = client.delegations().create(&CreateDelegationRequest {
    ///     from_agent_id: "a".into(),
    ///     to_agent_id: "b".into(),
    ///     scope: vec!["read".into()],
    ///     ttl_seconds: Some(60),
    ///     restrictions: None,
    ///     parent_delegation_id: None,
    /// }).unwrap();
    /// assert!(!d.id.is_empty());
    /// ```
    pub fn create(&self, req: &CreateDelegationRequest) -> Result<Delegation> {
        let value: Value = self
            .client
            .request("POST", "/api/v1/delegations", Some(req))?;
        // Response may be `{"delegation": {...}}` or the delegation directly.
        if value.get("delegation").is_some() {
            let resp: DelegationCreateResponse = serde_json::from_value(value)?;
            return resp
                .delegation
                .ok_or_else(|| crate::error::AgentTrustError::Api {
                    message: "missing delegation in response".to_string(),
                    code: "DELEGATION_MISSING".to_string(),
                    status: 500,
                });
        }
        let delegation: Delegation = serde_json::from_value(value)?;
        Ok(delegation)
    }

    /// Retrieve a delegation by ID.
    ///
    /// Calls `GET /api/v1/delegations/{id}`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let d = client.delegations().get("del-1").unwrap();
    /// println!("scope: {:?}", d.scope);
    /// ```
    pub fn get(&self, delegation_id: &str) -> Result<Delegation> {
        let path = format!("/api/v1/delegations/{}", delegation_id);
        self.client.request("GET", &path, None::<&()>)
    }

    /// List all delegations visible to the caller.
    ///
    /// Calls `GET /api/v1/delegations`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let delegations = client.delegations().list().unwrap();
    /// println!("{} delegations", delegations.len());
    /// ```
    pub fn list(&self) -> Result<Vec<Delegation>> {
        let value: Value = self
            .client
            .request("GET", "/api/v1/delegations", None::<&()>)?;
        if let Value::Array(_) = &value {
            let v: Vec<Delegation> = serde_json::from_value(value)?;
            return Ok(v);
        }
        let resp: DelegationListResponse = serde_json::from_value(value)?;
        Ok(resp.delegations.unwrap_or_default())
    }

    /// Revoke a delegation immediately.
    ///
    /// Calls `DELETE /api/v1/delegations/{id}`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// client.delegations().revoke("del-1").unwrap();
    /// ```
    pub fn revoke(&self, delegation_id: &str) -> Result<()> {
        let path = format!("/api/v1/delegations/{}", delegation_id);
        self.client
            .request_no_response("DELETE", &path, None::<&()>)
    }

    /// Initialize an AgentTrust session from an existing delegation.
    ///
    /// Calls `POST /api/v1/delegations/{id}/session`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let session = client.delegations().init_session("del-1").unwrap();
    /// println!("session: {}", session.session_id);
    /// ```
    pub fn init_session(&self, delegation_id: &str) -> Result<Session> {
        let path = format!("/api/v1/delegations/{}/session", delegation_id);
        self.client.request("POST", &path, None::<&()>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AgentTrustError;
    use mockito::Server;

    fn delegation_body() -> &'static str {
        r#"{
            "id":"del-1",
            "from_agent_id":"a",
            "to_agent_id":"b",
            "scope":["files:read"],
            "expires_at":"2030-01-01T00:00:00Z",
            "created_at":"2026-01-01T00:00:00Z"
        }"#
    }

    #[test]
    fn test_create_success_wrapped() {
        let mut srv = Server::new();
        let body = format!(r#"{{"delegation":{}}}"#, delegation_body());
        let mock = srv
            .mock("POST", "/api/v1/delegations")
            .with_status(200)
            .with_body(body)
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let d = client
            .delegations()
            .create(&CreateDelegationRequest {
                from_agent_id: "a".into(),
                to_agent_id: "b".into(),
                scope: vec!["files:read".into()],
                ttl_seconds: Some(3600),
                restrictions: None,
                parent_delegation_id: None,
            })
            .unwrap();
        assert_eq!(d.id, "del-1");
        assert_eq!(d.scope, vec!["files:read"]);
        mock.assert();
    }

    #[test]
    fn test_get_not_found() {
        let mut srv = Server::new();
        let mock = srv
            .mock("GET", "/api/v1/delegations/missing")
            .with_status(404)
            .with_body(r#"{"message":"not found"}"#)
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let err = client.delegations().get("missing").unwrap_err();
        assert!(matches!(err, AgentTrustError::NotFound { .. }));
        mock.assert();
    }

    #[test]
    fn test_list_array_response() {
        let mut srv = Server::new();
        let body = format!("[{}]", delegation_body());
        let mock = srv
            .mock("GET", "/api/v1/delegations")
            .with_status(200)
            .with_body(body)
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let list = client.delegations().list().unwrap();
        assert_eq!(list.len(), 1);
        mock.assert();
    }

    #[test]
    fn test_revoke_server_error() {
        let mut srv = Server::new();
        let mock = srv
            .mock("DELETE", "/api/v1/delegations/del-1")
            .with_status(500)
            .with_body(r#"{"message":"boom"}"#)
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let err = client.delegations().revoke("del-1").unwrap_err();
        match err {
            AgentTrustError::Api { status, .. } => assert_eq!(status, 500),
            other => panic!("unexpected: {:?}", other),
        }
        mock.assert();
    }
}
