//! Auto-managed agent runtime credentials.
//!
//! [`AgentCredentials`] issues a WIMSE token via the proof-of-possession flow,
//! caches it, refreshes it before expiry, and produces per-request
//! `Authorization: Bearer` + `DPoP` headers. The private key never leaves the
//! key store — both the PoP signature (at issuance) and the DPoP proof (per
//! request) are signed through it.
//!
//! ```no_run
//! use agenttrustid::{AgentTrustClient, AgentCredentials};
//! use agenttrustid::keys::{generate_agent_key, InMemoryKeyStore, KeyStore};
//!
//! let kp = generate_agent_key().unwrap();
//! let mut ks = InMemoryKeyStore::new();
//! ks.store("agent-1", &kp.private_key_pem).unwrap();
//!
//! let client = AgentTrustClient::builder().base_url("http://localhost:8080").build().unwrap();
//! let creds = AgentCredentials::new(&client, ks, "agent-1", &kp.public_key_pem);
//! let client = client.with_agent_credentials(creds);
//! // client.actions().check(..) now carries the WIMSE bearer + a DPoP proof.
//! ```

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::client::AgentTrustClient;
use crate::dpop::mint_dpop_proof_with_key_store;
use crate::error::Result;
use crate::keys::KeyStore;
use crate::models::IssueWIMSETokenRequest;

/// How long before a WIMSE token's expiry the manager proactively re-issues, so
/// a request never goes out with an about-to-expire token.
const CREDENTIAL_REFRESH_SKEW_SECS: u64 = 60;

struct TokenCache {
    token: String,
    expires_at: u64, // epoch seconds
}

/// Manages an agent's runtime authentication. Safe for concurrent use.
pub struct AgentCredentials {
    client: Box<AgentTrustClient>,
    base_url: String,
    ks: Box<dyn KeyStore + Send + Sync>,
    agent_id: String,
    public_key_pem: String,
    audience: Option<Vec<String>>,
    ttl_seconds: Option<u64>,
    cache: Mutex<TokenCache>,
}

impl AgentCredentials {
    /// Build a credential manager for an agent. `public_key_pem` is the agent's
    /// registered public key (used to populate DPoP proofs); the matching private
    /// key must be held in `key_store` under `agent_id`.
    pub fn new(
        client: &AgentTrustClient,
        key_store: impl KeyStore + Send + Sync + 'static,
        agent_id: impl Into<String>,
        public_key_pem: impl Into<String>,
    ) -> Self {
        Self::with_options(client, key_store, agent_id, public_key_pem, None, None)
    }

    /// Like [`new`](Self::new) but sets the WIMSE token audience and/or TTL.
    pub fn with_options(
        client: &AgentTrustClient,
        key_store: impl KeyStore + Send + Sync + 'static,
        agent_id: impl Into<String>,
        public_key_pem: impl Into<String>,
        audience: Option<Vec<String>>,
        ttl_seconds: Option<u64>,
    ) -> Self {
        AgentCredentials {
            client: Box::new(client.clone_for_credentials()),
            base_url: client.base_url().to_string(),
            ks: Box::new(key_store),
            agent_id: agent_id.into(),
            public_key_pem: public_key_pem.into(),
            audience,
            ttl_seconds,
            cache: Mutex::new(TokenCache {
                token: String::new(),
                expires_at: 0,
            }),
        }
    }

    /// Return a currently-valid WIMSE token, issuing or refreshing one via the
    /// proof-of-possession flow when the cache is empty or near expiry.
    ///
    /// # Errors
    ///
    /// Returns an error if token issuance fails.
    pub fn token(&self) -> Result<String> {
        let mut cache = self.cache.lock().expect("credential cache poisoned");
        let now = now_secs();
        if !cache.token.is_empty() && cache.expires_at > now + CREDENTIAL_REFRESH_SKEW_SECS {
            return Ok(cache.token.clone());
        }

        let req = IssueWIMSETokenRequest {
            agent_id: self.agent_id.clone(),
            audience: self.audience.clone(),
            ttl_seconds: self.ttl_seconds,
            ..Default::default()
        };
        let resp = self.client.wimse().issue_token_with_proof(&req, &*self.ks)?;
        cache.token = resp.token.clone();
        cache.expires_at = parse_expiry(&resp.expires_at);
        Ok(cache.token.clone())
    }

    /// Return the headers to attach to a runtime request for the given method and
    /// request path: a Bearer WIMSE token plus a fresh DPoP proof bound to the
    /// request (htu = base URL + path) and the token (ath).
    ///
    /// # Errors
    ///
    /// Returns an error if token issuance or proof minting fails.
    pub fn runtime_headers(&self, method: &str, path: &str) -> Result<Vec<(String, String)>> {
        let token = self.token()?;
        let url = format!("{}{}", self.base_url, path);
        let proof = mint_dpop_proof_with_key_store(
            &*self.ks,
            &self.agent_id,
            &self.public_key_pem,
            method,
            &url,
            &token,
        )?;
        Ok(vec![
            ("Authorization".to_string(), format!("Bearer {token}")),
            ("DPoP".to_string(), proof),
        ])
    }

    /// Clear the cached token, forcing a fresh issuance on the next call.
    pub fn invalidate(&self) {
        let mut cache = self.cache.lock().expect("credential cache poisoned");
        cache.token.clear();
        cache.expires_at = 0;
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse an RFC 3339 expiry to epoch seconds; on failure fall back to a
/// conservative short window so the manager re-issues soon.
fn parse_expiry(s: &str) -> u64 {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.timestamp().max(0) as u64)
        .unwrap_or_else(|_| now_secs() + 300)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{generate_agent_key, InMemoryKeyStore, KeyStore};
    use mockito::{Matcher, Server, ServerGuard};

    fn setup() -> (ServerGuard, AgentTrustClient, InMemoryKeyStore, String) {
        let kp = generate_agent_key().unwrap();
        let mut ks = InMemoryKeyStore::new();
        ks.store("agent-1", &kp.private_key_pem).unwrap();
        let srv = Server::new();
        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        (srv, client, ks, kp.public_key_pem)
    }

    fn challenge_body() -> &'static str {
        r#"{"nonce":"server-nonce","expires_at":"2026-12-31T00:00:00Z"}"#
    }

    #[test]
    fn issues_and_caches_token() {
        let (mut srv, client, ks, pubpem) = setup();
        let challenge = srv
            .mock("POST", "/api/v1/agents/agent-1/challenge")
            .with_body(challenge_body())
            .expect_at_least(1)
            .create();
        // Far-future expiry → second token() must hit the cache, not re-issue.
        let token = srv
            .mock("POST", "/api/v1/wimse/token")
            .with_body(r#"{"token":"wimse-tok","expires_at":"2099-01-01T00:00:00Z"}"#)
            .expect(1)
            .create();

        let creds = AgentCredentials::new(&client, ks, "agent-1", &pubpem);
        assert_eq!(creds.token().unwrap(), "wimse-tok");
        assert_eq!(creds.token().unwrap(), "wimse-tok");

        challenge.assert();
        token.assert();
    }

    #[test]
    fn runtime_headers_carry_bearer_and_dpop() {
        let (mut srv, client, ks, pubpem) = setup();
        srv.mock("POST", "/api/v1/agents/agent-1/challenge")
            .with_body(challenge_body())
            .create();
        srv.mock("POST", "/api/v1/wimse/token")
            .with_body(r#"{"token":"wimse-tok","expires_at":"2099-01-01T00:00:00Z"}"#)
            .create();

        let creds = AgentCredentials::new(&client, ks, "agent-1", &pubpem);
        let headers = creds
            .runtime_headers("POST", "/api/v1/agenttrust/check")
            .unwrap();
        let map: std::collections::HashMap<_, _> = headers.into_iter().collect();
        assert_eq!(map["Authorization"], "Bearer wimse-tok");
        assert_eq!(map["DPoP"].split('.').count(), 3);
    }

    #[test]
    fn check_attaches_bearer_and_dpop() {
        let (mut srv, client, ks, pubpem) = setup();
        srv.mock("POST", "/api/v1/agents/agent-1/challenge")
            .with_body(challenge_body())
            .create();
        srv.mock("POST", "/api/v1/wimse/token")
            .with_body(r#"{"token":"wimse-tok","expires_at":"2099-01-01T00:00:00Z"}"#)
            .create();
        let check = srv
            .mock("POST", "/api/v1/agenttrust/check")
            .match_header("authorization", "Bearer wimse-tok")
            .match_header("dpop", Matcher::Regex(r"^.+\..+\..+$".to_string()))
            .with_body(r#"{"allowed":true,"guard_tier":"fast"}"#)
            .expect(1)
            .create();

        let creds = AgentCredentials::new(&client, ks, "agent-1", &pubpem);
        let client = client.with_agent_credentials(creds);

        let result = client
            .actions()
            .check(&crate::models::ActionCheckRequest {
                agent_id: "agent-1".into(),
                action: "tool_call".into(),
                tool_name: "read_file".into(),
                tool_input_summary: String::new(),
                session_id: String::new(),
                action_effect: None,
            })
            .unwrap();
        assert!(result.allowed);
        check.assert();
    }

    #[test]
    fn invalidate_forces_reissue() {
        let (mut srv, client, ks, pubpem) = setup();
        srv.mock("POST", "/api/v1/agents/agent-1/challenge")
            .with_body(challenge_body())
            .expect_at_least(2)
            .create();
        let token = srv
            .mock("POST", "/api/v1/wimse/token")
            .with_body(r#"{"token":"wimse-tok","expires_at":"2099-01-01T00:00:00Z"}"#)
            .expect(2)
            .create();

        let creds = AgentCredentials::new(&client, ks, "agent-1", &pubpem);
        creds.token().unwrap();
        creds.invalidate();
        creds.token().unwrap();
        token.assert();
    }
}
