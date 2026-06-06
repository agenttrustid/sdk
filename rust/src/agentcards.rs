//! Agent Cards API — generate, fetch, and publish A2A-compatible agent cards.
//!
//! Agent cards are JSON descriptors that advertise an agent's identity,
//! capabilities, and trust posture so other agents can discover and call it
//! via the A2A protocol.
//!
//! # Example
//!
//! ```rust,no_run
//! use agenttrustid::AgentTrustClient;
//!
//! let client = AgentTrustClient::builder().build().unwrap();
//!
//! // Generate a card for an agent
//! let card = client.agentcards().generate("agent-123").unwrap();
//! println!("Card name: {}", card.name);
//!
//! // Fetch the current card
//! let card = client.agentcards().get("agent-123").unwrap();
//!
//! // Publish (make publicly discoverable)
//! let published = client.agentcards().publish("agent-123").unwrap();
//! ```

use crate::client::AgentTrustClient;
use crate::error::Result;
use crate::models::AgentCard;

/// Provides agent-card management operations.
///
/// Obtained via [`AgentTrustClient::agentcards()`].
pub struct AgentCards<'a> {
    pub(crate) client: &'a AgentTrustClient,
}

impl<'a> AgentCards<'a> {
    /// Generate a new agent card for `agent_id`.
    ///
    /// Calls `POST /api/v1/agents/{id}/card`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let card = client.agentcards().generate("agent-123").unwrap();
    /// assert!(!card.name.is_empty());
    /// ```
    pub fn generate(&self, agent_id: &str) -> Result<AgentCard> {
        let path = format!("/api/v1/agents/{}/card", agent_id);
        self.client.request("POST", &path, None::<&()>)
    }

    /// Fetch the current agent card for `agent_id`.
    ///
    /// Calls `GET /api/v1/agents/{id}/card`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let card = client.agentcards().get("agent-123").unwrap();
    /// println!("Trust score: {}", card.trust_score());
    /// ```
    pub fn get(&self, agent_id: &str) -> Result<AgentCard> {
        let path = format!("/api/v1/agents/{}/card", agent_id);
        self.client.request("GET", &path, None::<&()>)
    }

    /// Publish an agent card so it is discoverable at
    /// `/a2a/agents/{id}/agent.json`.
    ///
    /// Calls `PUT /api/v1/agents/{id}/card/publish`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let card = client.agentcards().publish("agent-123").unwrap();
    /// println!("Published at: {:?}", card.primary_url());
    /// ```
    pub fn publish(&self, agent_id: &str) -> Result<AgentCard> {
        let path = format!("/api/v1/agents/{}/card/publish", agent_id);
        self.client.request("PUT", &path, None::<&()>)
    }

    /// Fetch a publicly published agent card without authentication.
    ///
    /// Calls `GET /a2a/agents/{id}/agent.json`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let card = client.agentcards().get_public("agent-123").unwrap();
    /// println!("Public card: {}", card.name);
    /// ```
    pub fn get_public(&self, agent_id: &str) -> Result<AgentCard> {
        let path = format!("/a2a/agents/{}/agent.json", agent_id);
        self.client.request("GET", &path, None::<&()>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AgentTrustError;
    use mockito::Server;

    /// A representative A2A v1.0 agent card as published by the server.
    fn card_body() -> &'static str {
        r#"{
            "name": "test-agent",
            "description": "A test agent",
            "version": "1.0.0",
            "supportedInterfaces": [
                {
                    "url": "https://ati.example/a2a/agents/agent-123",
                    "protocolBinding": "JSONRPC",
                    "protocolVersion": "1.0"
                }
            ],
            "provider": {"organization": "ATI", "url": "https://agenttrust.id"},
            "capabilities": {
                "streaming": true,
                "pushNotifications": false,
                "extensions": [
                    {
                        "uri": "https://agenttrust.id/ext/trust/v1",
                        "description": "ATI trust posture",
                        "params": {"ati_trust_score": 92, "ati_guardian_tier": "fast"}
                    }
                ]
            },
            "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
            "defaultInputModes": ["text/plain"],
            "defaultOutputModes": ["text/plain"],
            "skills": [
                {"id": "search", "name": "Search", "description": "Web search", "tags": ["web", "lookup"]}
            ],
            "signatures": [
                {"protected": "eyJhbGciOiJFUzI1NiJ9", "signature": "c2ln"}
            ]
        }"#
    }

    #[test]
    fn test_generate_success() {
        let mut srv = Server::new();
        let mock = srv
            .mock("POST", "/api/v1/agents/agent-123/card")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(card_body())
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let card = client.agentcards().generate("agent-123").unwrap();
        assert_eq!(card.name, "test-agent");
        assert!(card.capabilities.streaming);
        assert_eq!(card.trust_score(), 92.0);
        mock.assert();
    }

    #[test]
    fn test_card_deserializes_v1_card() {
        // A full v1.0 card must parse, and the convenience accessors must read
        // the new locations (supportedInterfaces + trust extension).
        let card: AgentCard = serde_json::from_str(card_body()).unwrap();

        assert_eq!(card.name, "test-agent");
        assert_eq!(card.version, "1.0.0");
        assert_eq!(
            card.primary_url(),
            Some("https://ati.example/a2a/agents/agent-123")
        );
        assert_eq!(card.supported_interfaces[0].protocol_binding, "JSONRPC");
        assert_eq!(card.trust_score(), 92.0);

        // skills + tags
        assert_eq!(card.skills.len(), 1);
        assert_eq!(card.skills[0].id, "search");
        assert_eq!(card.skills[0].tags, vec!["web", "lookup"]);

        // signatures
        assert_eq!(card.signatures.len(), 1);
        assert_eq!(card.signatures[0].protected, "eyJhbGciOiJFUzI1NiJ9");

        // security schemes
        let schemes = card.security_schemes.as_ref().unwrap();
        assert_eq!(schemes["bearer"].r#type, "http");
        assert_eq!(schemes["bearer"].scheme.as_deref(), Some("bearer"));

        // provider
        assert_eq!(card.provider.as_ref().unwrap().organization, "ATI");
    }

    #[test]
    fn test_legacy_card_still_parses() {
        // A pre-v1.0 card with only a top-level `url` and no new fields must
        // still deserialize, and primary_url() must fall back to it.
        let legacy = r#"{
            "name": "legacy-agent",
            "url": "https://ati.example/a2a/agents/legacy/agent.json",
            "version": "0.9"
        }"#;
        let card: AgentCard = serde_json::from_str(legacy).unwrap();
        assert_eq!(card.name, "legacy-agent");
        assert_eq!(
            card.primary_url(),
            Some("https://ati.example/a2a/agents/legacy/agent.json")
        );
        // No trust extension present -> default score.
        assert_eq!(card.trust_score(), 0.0);
        assert!(card.skills.is_empty());
    }

    #[test]
    fn test_get_not_found() {
        let mut srv = Server::new();
        let mock = srv
            .mock("GET", "/api/v1/agents/missing/card")
            .with_status(404)
            .with_body(r#"{"message":"agent not found"}"#)
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let err = client.agentcards().get("missing").unwrap_err();
        assert!(matches!(err, AgentTrustError::NotFound { .. }));
        mock.assert();
    }

    #[test]
    fn test_publish_server_error() {
        let mut srv = Server::new();
        let mock = srv
            .mock("PUT", "/api/v1/agents/agent-123/card/publish")
            .with_status(500)
            .with_body(r#"{"message":"internal error"}"#)
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let err = client.agentcards().publish("agent-123").unwrap_err();
        match err {
            AgentTrustError::Api { status, .. } => assert_eq!(status, 500),
            other => panic!("expected Api error, got {:?}", other),
        }
        mock.assert();
    }

    #[test]
    fn test_get_public_success() {
        let mut srv = Server::new();
        let mock = srv
            .mock("GET", "/a2a/agents/agent-123/agent.json")
            .with_status(200)
            .with_body(card_body())
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let card = client.agentcards().get_public("agent-123").unwrap();
        assert_eq!(card.skills.len(), 1);
        mock.assert();
    }
}
