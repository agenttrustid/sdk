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
//!     ..Default::default()
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
use crate::keys::KeyStore;
use crate::models::{
    ChallengeResponse, IssueWIMSETokenRequest, PoPProof, VerifyWIMSETokenRequest,
    VerifyWIMSETokenResponse, WIMSETokenResponse,
};
use std::time::{SystemTime, UNIX_EPOCH};

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
    ///     ..Default::default()
    /// }).unwrap();
    /// println!("workload {}", issued.workload_id);
    /// ```
    pub fn issue_token(&self, req: &IssueWIMSETokenRequest) -> Result<WIMSETokenResponse> {
        self.client
            .request("POST", "/api/v1/wimse/token", Some(req))
    }

    /// Request a single-use proof-of-possession challenge nonce for an agent.
    ///
    /// Calls `POST /api/v1/agents/{agent_id}/challenge`.
    pub fn challenge(&self, agent_id: &str) -> Result<ChallengeResponse> {
        let path = format!("/api/v1/agents/{}/challenge", agent_id);
        self.client.request("POST", &path, None::<&()>)
    }

    /// Issue a WIMSE token using proof-of-possession.
    ///
    /// Fetches a challenge for the agent, signs the canonical challenge message
    /// with the agent's key from `key_store`, and issues with the proof attached
    /// so the resulting token is bound to the agent key (`cnf.jkt`). Required when
    /// the org enables proof-of-possession.
    pub fn issue_token_with_proof(
        &self,
        req: &IssueWIMSETokenRequest,
        key_store: &dyn KeyStore,
    ) -> Result<WIMSETokenResponse> {
        let challenge = self.challenge(&req.agent_id)?;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let audience = req
            .audience
            .as_ref()
            .map(|a| a.join(","))
            .unwrap_or_default();
        // Canonical message must stay byte-identical to the server's
        // crypto.PoPMessage: "pop-v1:<nonce>:<agentID>:<audience>:<ts>".
        let message = format!(
            "pop-v1:{}:{}:{}:{}",
            challenge.nonce, req.agent_id, audience, ts
        );
        let sig = key_store.sign(&req.agent_id, message.as_bytes())?;

        let mut signed = req.clone();
        signed.proof = Some(PoPProof {
            nonce: challenge.nonce,
            ts,
            signature: base64url_no_pad(&sig),
        });
        self.issue_token(&signed)
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
    ///     ..Default::default()
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

/// Encode bytes as base64url without padding (RFC 4648 §5), matching the
/// canonical proof-of-possession signature encoding the server accepts.
fn base64url_no_pad(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 63) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AgentTrustError;
    use crate::keys::{generate_agent_key, parse_public_key, InMemoryKeyStore, KeyStore};
    use ed25519_dalek::Verifier;
    use mockito::Server;

    #[test]
    fn test_base64url_no_pad_matches_reference() {
        // Known RFC 4648 vectors (base64url, no padding).
        assert_eq!(base64url_no_pad(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64url_no_pad(b"fo"), "Zm8");
        assert_eq!(base64url_no_pad(&[0xff, 0xff, 0xfe]), "___-");
    }

    #[test]
    fn test_issue_token_with_proof_signs_canonical_message() {
        let kp = generate_agent_key().unwrap();
        let mut ks = InMemoryKeyStore::new();
        ks.store("agent-1", &kp.private_key_pem).unwrap();

        let mut srv = Server::new();
        let challenge_mock = srv
            .mock("POST", "/api/v1/agents/agent-1/challenge")
            .with_status(200)
            .with_body(r#"{"nonce":"server-nonce-xyz","expires_at":"2026-12-31T00:00:00Z"}"#)
            .create();
        // Capture the issued request body to assert the proof it carries.
        let token_mock = srv
            .mock("POST", "/api/v1/wimse/token")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"proof":{"nonce":"server-nonce-xyz"}}"#.to_string(),
            ))
            .with_status(200)
            .with_body(r#"{"token":"eyJ.bound","workload_id":"w","trust_domain":"ati","expires_at":"x"}"#)
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let resp = client
            .wimse()
            .issue_token_with_proof(
                &IssueWIMSETokenRequest {
                    agent_id: "agent-1".into(),
                    audience: Some(vec!["https://api.example.com".into()]),
                    ..Default::default()
                },
                &ks,
            )
            .unwrap();
        assert_eq!(resp.token, "eyJ.bound");
        challenge_mock.assert();
        token_mock.assert();
    }

    #[test]
    fn test_pop_signature_verifies_against_public_key() {
        // Reproduce the SDK's signing and confirm the signature verifies under the
        // canonical message — exactly what the server's VerifyPoP checks.
        let kp = generate_agent_key().unwrap();
        let mut ks = InMemoryKeyStore::new();
        ks.store("agent-1", &kp.private_key_pem).unwrap();

        let nonce = "server-nonce-xyz";
        let ts: i64 = 1_781_974_465;
        let audience = "https://api.example.com";
        let message = format!("pop-v1:{}:{}:{}:{}", nonce, "agent-1", audience, ts);
        let sig_bytes = ks.sign("agent-1", message.as_bytes()).unwrap();

        let vk = parse_public_key(&kp.public_key_pem).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        assert!(vk.verify(message.as_bytes(), &sig).is_ok());
    }

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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
            })
            .unwrap_err();
        match err {
            AgentTrustError::Api { status, .. } => assert_eq!(status, 500),
            other => panic!("unexpected: {:?}", other),
        }
        mock.assert();
    }
}
