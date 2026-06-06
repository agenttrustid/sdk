//! Cross-organization OIDC federation.
//!
//! Use this API to register external OIDC providers, verify federated tokens,
//! issue opaque federation tokens for AgentTrust ID agents, and bridge federated identities into local
//! AgentTrust sessions.
//!
//! # Example
//!
//! ```rust,no_run
//! use agenttrustid::{AgentTrustClient, RegisterFederationProviderRequest, VerifyFederatedTokenRequest};
//!
//! let client = AgentTrustClient::builder().build().unwrap();
//!
//! let provider = client.federation().register_provider(&RegisterFederationProviderRequest {
//!     issuer: "https://issuer.example.com".to_string(),
//!     name: "Example IdP".to_string(),
//!     trust_level: Some("standard".to_string()),
//! }).unwrap();
//!
//! let result = client.federation().introspect_token(&VerifyFederatedTokenRequest {
//!     token: "eyJ...".to_string(),
//!     issuer_hint: None,
//! }).unwrap();
//!
//! if result.valid {
//!     println!("Federated agent: {:?}", result.agent_id);
//! }
//! ```

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::AgentTrustClient;
use crate::error::Result;
use crate::models::{
    FederationProvider, IssueFederatedIDTokenRequest, IssueFederatedIDTokenResult,
    RegisterFederationProviderRequest, Session, VerifyFederatedTokenRequest,
    VerifyFederatedTokenResult,
};

/// Provides OIDC federation operations.
///
/// Obtained via [`AgentTrustClient::federation()`].
pub struct Federation<'a> {
    pub(crate) client: &'a AgentTrustClient,
}

#[derive(Debug, Deserialize)]
struct ProviderRegisterResponse {
    #[serde(default)]
    provider: Option<FederationProvider>,
}

#[derive(Debug, Deserialize)]
struct ProviderListResponse {
    #[serde(default)]
    providers: Option<Vec<FederationProvider>>,
}

#[derive(Debug, Serialize)]
struct IssueFederationTokenRequest<'a> {
    agent_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<&'a str>,
    #[serde(skip_serializing_if = "slice_is_empty")]
    scopes: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u64>,
}

fn slice_is_empty<T>(items: &[T]) -> bool {
    items.is_empty()
}

impl<'a> Federation<'a> {
    /// Register an OIDC provider.
    ///
    /// Calls `POST /api/v1/federation/providers`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::{AgentTrustClient, RegisterFederationProviderRequest};
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let p = client.federation().register_provider(&RegisterFederationProviderRequest {
    ///     issuer: "https://idp".into(),
    ///     name: "idp".into(),
    ///     trust_level: None,
    /// }).unwrap();
    /// assert!(!p.id.is_empty());
    /// ```
    pub fn register_provider(
        &self,
        req: &RegisterFederationProviderRequest,
    ) -> Result<FederationProvider> {
        let value: Value =
            self.client
                .request("POST", "/api/v1/federation/providers", Some(req))?;
        if value.get("provider").is_some() {
            let resp: ProviderRegisterResponse = serde_json::from_value(value)?;
            return resp
                .provider
                .ok_or_else(|| crate::error::AgentTrustError::Api {
                    message: "missing provider in response".to_string(),
                    code: "PROVIDER_MISSING".to_string(),
                    status: 500,
                });
        }
        let p: FederationProvider = serde_json::from_value(value)?;
        Ok(p)
    }

    /// List registered OIDC providers.
    ///
    /// Calls `GET /api/v1/federation/providers`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// for p in client.federation().list_providers().unwrap() {
    ///     println!("{}: {}", p.name, p.issuer);
    /// }
    /// ```
    pub fn list_providers(&self) -> Result<Vec<FederationProvider>> {
        let value: Value =
            self.client
                .request("GET", "/api/v1/federation/providers", None::<&()>)?;
        if let Value::Array(_) = &value {
            let v: Vec<FederationProvider> = serde_json::from_value(value)?;
            return Ok(v);
        }
        let resp: ProviderListResponse = serde_json::from_value(value)?;
        Ok(resp.providers.unwrap_or_default())
    }

    /// Delete a registered OIDC provider.
    ///
    /// Calls `DELETE /api/v1/federation/providers/{id}`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// client.federation().delete_provider("prov-1").unwrap();
    /// ```
    pub fn delete_provider(&self, provider_id: &str) -> Result<()> {
        let path = format!("/api/v1/federation/providers/{}", provider_id);
        self.client
            .request_no_response("DELETE", &path, None::<&()>)
    }

    /// Issue an opaque federation token for an AgentTrust ID agent.
    ///
    /// Calls `POST /api/v1/federation/tokens/issue`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::{AgentTrustClient, IssueFederatedIDTokenRequest};
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let t = client.federation().issue_token(
    ///     "agent-1",
    ///     &IssueFederatedIDTokenRequest::default(),
    /// ).unwrap();
    /// println!("token: {}", t.id_token);
    /// ```
    pub fn issue_token(
        &self,
        agent_id: &str,
        req: &IssueFederatedIDTokenRequest,
    ) -> Result<IssueFederatedIDTokenResult> {
        let body = IssueFederationTokenRequest {
            agent_id,
            audience: req.audience.as_deref(),
            scopes: req.scopes.as_slice(),
            ttl: req.ttl,
        };
        self.client
            .request("POST", "/api/v1/federation/tokens/issue", Some(&body))
    }

    /// Verify (introspect) a federated token.
    ///
    /// Calls `POST /api/v1/federation/tokens/verify`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::{AgentTrustClient, VerifyFederatedTokenRequest};
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let r = client.federation().introspect_token(&VerifyFederatedTokenRequest {
    ///     token: "eyJ...".into(),
    ///     issuer_hint: None,
    /// }).unwrap();
    /// println!("valid: {}", r.valid);
    /// ```
    pub fn introspect_token(
        &self,
        req: &VerifyFederatedTokenRequest,
    ) -> Result<VerifyFederatedTokenResult> {
        self.client
            .request("POST", "/api/v1/federation/tokens/verify", Some(req))
    }

    /// Revoke a previously issued federated token.
    ///
    /// Calls `POST /api/v1/federation/tokens/revoke`. The endpoint accepts
    /// `{"token": "..."}` and returns no body.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// client.federation().revoke_token("eyJ...").unwrap();
    /// ```
    pub fn revoke_token(&self, token: &str) -> Result<()> {
        #[derive(serde::Serialize)]
        struct RevokeBody<'a> {
            token: &'a str,
        }
        self.client.request_no_response(
            "POST",
            "/api/v1/federation/tokens/revoke",
            Some(&RevokeBody { token }),
        )
    }

    /// Initialize a local AgentTrust session from a federated token.
    ///
    /// Calls `POST /api/v1/federation/sessions/init`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::{AgentTrustClient, VerifyFederatedTokenRequest};
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let s = client.federation().init_session(&VerifyFederatedTokenRequest {
    ///     token: "eyJ...".into(),
    ///     issuer_hint: None,
    /// }).unwrap();
    /// println!("{}", s.session_id);
    /// ```
    pub fn init_session(&self, req: &VerifyFederatedTokenRequest) -> Result<Session> {
        self.client
            .request("POST", "/api/v1/federation/sessions/init", Some(req))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AgentTrustError;
    use mockito::Server;

    fn provider_body() -> &'static str {
        r#"{
            "id":"prov-1","org_id":"o1","issuer":"https://idp",
            "name":"idp","jwks_uri":"https://idp/.well-known/jwks.json",
            "trust_level":"standard","status":"active"
        }"#
    }

    #[test]
    fn test_register_provider_wrapped() {
        let mut srv = Server::new();
        let body = format!(r#"{{"provider":{}}}"#, provider_body());
        let mock = srv
            .mock("POST", "/api/v1/federation/providers")
            .with_status(200)
            .with_body(body)
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let p = client
            .federation()
            .register_provider(&RegisterFederationProviderRequest {
                issuer: "https://idp".into(),
                name: "idp".into(),
                trust_level: None,
            })
            .unwrap();
        assert_eq!(p.id, "prov-1");
        assert_eq!(p.trust_level, "standard");
        mock.assert();
    }

    #[test]
    fn test_list_providers_validation_error() {
        let mut srv = Server::new();
        let mock = srv
            .mock("GET", "/api/v1/federation/providers")
            .with_status(400)
            .with_body(r#"{"message":"invalid query"}"#)
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let err = client.federation().list_providers().unwrap_err();
        assert!(matches!(err, AgentTrustError::Validation { .. }));
        mock.assert();
    }

    #[test]
    fn test_introspect_token_success() {
        let mut srv = Server::new();
        let mock = srv
            .mock("POST", "/api/v1/federation/tokens/verify")
            .with_status(200)
            .with_body(r#"{"valid":true,"agent_id":"a1","issuer":"https://idp"}"#)
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let r = client
            .federation()
            .introspect_token(&VerifyFederatedTokenRequest {
                token: "eyJ".into(),
                issuer_hint: None,
            })
            .unwrap();
        assert!(r.valid);
        assert_eq!(r.agent_id.as_deref(), Some("a1"));
        mock.assert();
    }

    #[test]
    fn test_revoke_token_server_error() {
        let mut srv = Server::new();
        let mock = srv
            .mock("POST", "/api/v1/federation/tokens/revoke")
            .with_status(500)
            .with_body(r#"{"message":"failed"}"#)
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let err = client.federation().revoke_token("eyJ").unwrap_err();
        match err {
            AgentTrustError::Api { status, .. } => assert_eq!(status, 500),
            other => panic!("unexpected: {:?}", other),
        }
        mock.assert();
    }
}
