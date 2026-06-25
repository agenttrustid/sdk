//! Integration-style tests using mockito to mock the HTTP server.

use mockito::{Matcher, Server};
use std::env;

use crate::client::AgentTrustClient;
use crate::error::AgentTrustError;
use crate::guard::AgentTrustGuard;
use crate::models::*;

// ---------------------------------------------------------------------------
// Client creation tests
// ---------------------------------------------------------------------------

#[test]
fn test_client_builder_defaults() {
    let client = AgentTrustClient::builder().build().unwrap();
    assert_eq!(client.base_url, "http://localhost:8080");
    assert!(client.api_key.is_none());
}

#[test]
fn test_client_builder_custom() {
    let client = AgentTrustClient::builder()
        .base_url("http://custom:9090")
        .api_key("sk_test_123")
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    assert_eq!(client.base_url, "http://custom:9090");
    assert_eq!(client.api_key.as_deref(), Some("sk_test_123"));
}

#[test]
fn test_client_builder_trailing_slash_trimmed() {
    let client = AgentTrustClient::builder()
        .base_url("http://example.com/")
        .build()
        .unwrap();
    assert_eq!(client.base_url, "http://example.com");
}

#[test]
fn test_client_from_env() {
    // Set env vars for this test
    env::set_var("AGENTTRUST_URL", "http://env-url:8080");
    env::set_var("AGENTTRUST_API_KEY", "sk_env_key");

    let client = AgentTrustClient::from_env().unwrap();
    assert_eq!(client.base_url, "http://env-url:8080");
    assert_eq!(client.api_key.as_deref(), Some("sk_env_key"));

    // Cleanup
    env::remove_var("AGENTTRUST_URL");
    env::remove_var("AGENTTRUST_API_KEY");
}

#[test]
fn test_client_from_env_fallback() {
    env::remove_var("AGENTTRUST_URL");
    env::set_var("AGENTTRUST_BASE_URL", "http://fallback:8080");

    let client = AgentTrustClient::from_env().unwrap();
    assert_eq!(client.base_url, "http://fallback:8080");

    env::remove_var("AGENTTRUST_BASE_URL");
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

#[test]
fn test_health() {
    let mut srv = Server::new();

    let mock = srv
        .mock("GET", "/health")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"status":"healthy","service":"gateway","version":"1.0.0"}"#)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let health = client.health().unwrap();
    assert_eq!(health.status, "healthy");
    assert_eq!(health.service.as_deref(), Some("gateway"));
    assert_eq!(health.version.as_deref(), Some("1.0.0"));
    mock.assert();
}

// ---------------------------------------------------------------------------
// Agent CRUD
// ---------------------------------------------------------------------------

#[test]
fn test_agents_create_nested_response() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/agents")
        .match_header("X-API-Key", "sk_test")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "agent": {
                    "id": "agent-123",
                    "name": "test-agent",
                    "org_id": "org-1",
                    "framework": "langchain",
                    "public_key": "-----BEGIN PUBLIC KEY-----",
                    "status": "active",
                    "capabilities": ["web_search", "files:read"],
                    "metadata": {},
                    "created_at": "2026-01-01T00:00:00Z",
                    "private_key": "-----BEGIN PRIVATE KEY-----"
                }
            }"#,
        )
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .api_key("sk_test")
        .build()
        .unwrap();

    let agent = client
        .agents()
        .create(&CreateAgentRequest {
            name: "test-agent".to_string(),
            framework: "langchain".to_string(),
            capabilities: vec!["web_search".to_string(), "files:read".to_string()],
            ..Default::default()
        })
        .unwrap();

    assert_eq!(agent.id, "agent-123");
    assert_eq!(agent.name, "test-agent");
    assert_eq!(agent.framework, "langchain");
    assert_eq!(agent.status, "active");
    assert_eq!(agent.capabilities.len(), 2);
    // The private key is generated client-side, so the returned key is the real
    // local PKCS#8 PEM — not the server's stub.
    let pk = agent.private_key.as_deref().unwrap();
    assert!(pk.contains("-----BEGIN PRIVATE KEY-----"));
    assert_ne!(pk, "-----BEGIN PRIVATE KEY-----");
    mock.assert();
}

#[test]
fn test_agents_create_generates_and_registers_only_public_key() {
    let mut srv = Server::new();

    // Capture the request body and assert it carried a public key.
    let mock = srv
        .mock("POST", "/api/v1/agents")
        .match_body(Matcher::AllOf(vec![
            Matcher::Regex("BEGIN PUBLIC KEY".to_string()),
            Matcher::Regex("\"public_key\"".to_string()),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"agent":{"id":"a","name":"n","org_id":"o","framework":"custom","status":"active","capabilities":[]}}"#,
        )
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let agent = client
        .agents()
        .create(&CreateAgentRequest {
            name: "n".to_string(),
            ..Default::default()
        })
        .unwrap();

    // Private key is held locally and attached to the returned agent.
    let pk = agent.private_key.as_deref().unwrap();
    assert!(pk.contains("BEGIN PRIVATE KEY"));
    // The local private key signs (its public half is verified directly in the
    // keys.rs unit tests).
    assert!(crate::keys::sign_with_private_key_pem(pk, b"challenge").is_ok());
    mock.assert();
}

#[test]
fn test_agents_create_with_supplied_public_key_does_not_generate() {
    let mut srv = Server::new();
    let mock = srv
        .mock("POST", "/api/v1/agents")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"agent":{"id":"a","name":"n","org_id":"o","framework":"custom","status":"active","capabilities":[]}}"#,
        )
        .create();

    let kp = crate::keys::generate_agent_key().unwrap();
    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let agent = client
        .agents()
        .create(&CreateAgentRequest {
            name: "n".to_string(),
            public_key: Some(kp.public_key_pem),
            ..Default::default()
        })
        .unwrap();

    // Nothing was generated locally, so no private key is attached.
    assert!(agent.private_key.is_none());
    mock.assert();
}

#[test]
fn test_agents_create_validation_error() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/agents")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"name is required"}"#)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let result = client.agents().create(&CreateAgentRequest {
        name: String::new(),
        ..Default::default()
    });

    assert!(result.is_err());
    match result.unwrap_err() {
        AgentTrustError::Validation { message, status } => {
            assert_eq!(message, "name is required");
            assert_eq!(status, 400);
        }
        e => panic!("expected Validation error, got: {:?}", e),
    }
    mock.assert();
}

#[test]
fn test_agents_get() {
    let mut srv = Server::new();

    let mock = srv
        .mock("GET", "/api/v1/agents/agent-123")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "id": "agent-123",
                "name": "my-agent",
                "org_id": "org-1",
                "framework": "custom",
                "status": "active",
                "capabilities": ["read"],
                "created_at": "2026-01-01T00:00:00Z"
            }"#,
        )
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let agent = client.agents().get("agent-123").unwrap();
    assert_eq!(agent.id, "agent-123");
    assert_eq!(agent.name, "my-agent");
    mock.assert();
}

#[test]
fn test_agents_get_not_found() {
    let mut srv = Server::new();

    let mock = srv
        .mock("GET", "/api/v1/agents/nonexistent")
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"agent not found"}"#)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let result = client.agents().get("nonexistent");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AgentTrustError::NotFound { .. }
    ));
    mock.assert();
}

#[test]
fn test_agents_list() {
    let mut srv = Server::new();

    let mock = srv
        .mock("GET", "/api/v1/agents")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "agents": [
                    {"id": "a1", "name": "agent-1", "status": "active", "framework": "custom", "capabilities": []},
                    {"id": "a2", "name": "agent-2", "status": "revoked", "framework": "langchain", "capabilities": ["search"]}
                ]
            }"#,
        )
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let agents = client.agents().list(None).unwrap();
    assert_eq!(agents.len(), 2);
    assert_eq!(agents[0].name, "agent-1");
    assert_eq!(agents[1].status, "revoked");
    mock.assert();
}

#[test]
fn test_agents_revoke() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/agents/agent-123/revoke")
        .match_body(Matcher::JsonString(
            r#"{"reason":"compromised"}"#.to_string(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"success": true}"#)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let result = client.agents().revoke("agent-123", "compromised");
    assert!(result.is_ok());
    mock.assert();
}

// ---------------------------------------------------------------------------
// Token issue / verify / revoke
// ---------------------------------------------------------------------------

#[test]
fn test_tokens_issue() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/agent-tokens/issue")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "token": "at_xK3z9abcdef",
                "agent_id": "agent-123",
                "scopes": ["files:read"],
                "audience": ["mcp://filesystem"],
                "issued_at": "2026-01-01T00:00:00Z",
                "expires_at": "2026-01-01T00:05:00Z",
                "token_id": "tok-456"
            }"#,
        )
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let token = client
        .tokens()
        .issue(&IssueTokenRequest {
            agent_id: "agent-123".to_string(),
            scope: vec!["files:read".to_string()],
            audience: vec!["mcp://filesystem".to_string()],
            ttl: 300,
        })
        .unwrap();

    assert!(token.token.starts_with("at_"));
    assert_eq!(token.agent_id, "agent-123");
    assert_eq!(token.scopes, vec!["files:read"]);
    assert_eq!(token.token_id.as_deref(), Some("tok-456"));
    mock.assert();
}

#[test]
fn test_tokens_introspect() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/agent-tokens/introspect")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "active": true,
                "agent_id": "agent-123",
                "org_id": "org-1",
                "scopes": ["files:read"],
                "reasoning": "capability match",
                "guard_tier": "fast",
                "confidence": 0.95,
                "latency_ms": 12
            }"#,
        )
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let result = client
        .tokens()
        .introspect(&IntrospectTokenRequest {
            token: "at_test".to_string(),
            target: Some("mcp://filesystem".to_string()),
            required_scopes: vec!["files:read".to_string()],
        })
        .unwrap();

    assert!(result.active);
    assert_eq!(result.agent_id.as_deref(), Some("agent-123"));
    assert_eq!(result.org_id.as_deref(), Some("org-1"));
    assert_eq!(result.reasoning.as_deref(), Some("capability match"));
    assert_eq!(result.guard_tier.as_deref(), Some("fast"));
    assert_eq!(result.confidence, Some(0.95));
    mock.assert();
}

#[test]
fn test_tokens_revoke() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/agent-tokens/revoke")
        .match_body(Matcher::JsonString(
            r#"{"token":"at_revoke_me","reason":"key_compromised"}"#.to_string(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"success": true}"#)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let result = client.tokens().revoke("at_revoke_me", "key_compromised");
    assert!(result.is_ok());
    mock.assert();
}

// ---------------------------------------------------------------------------
// Action check
// ---------------------------------------------------------------------------

#[test]
fn test_actions_check_allowed() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/agenttrust/check")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "allowed": true,
                "check_id": "chk-1",
                "confidence": 0.95,
                "guard_tier": "fast",
                "latency_ms": 12,
                "reason": "capability match"
            }"#,
        )
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let result = client
        .actions()
        .check(&ActionCheckRequest {
            agent_id: "agent-1".to_string(),
            tool_name: "web_search".to_string(),
            tool_input_summary: "search query".to_string(),
            ..Default::default()
        })
        .unwrap();

    assert!(result.allowed);
    assert_eq!(result.check_id.as_deref(), Some("chk-1"));
    assert_eq!(result.guard_tier.as_deref(), Some("fast"));
    mock.assert();
}

#[test]
fn test_actions_check_denied() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/agenttrust/check")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "allowed": false,
                "confidence": 0.95,
                "guard_tier": "fast",
                "reason": "capability not registered"
            }"#,
        )
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let result = client
        .actions()
        .check(&ActionCheckRequest {
            agent_id: "agent-1".to_string(),
            tool_name: "delete_all".to_string(),
            ..Default::default()
        })
        .unwrap();

    assert!(!result.allowed);
    assert_eq!(result.reason.as_deref(), Some("capability not registered"));
    mock.assert();
}

#[test]
fn test_actions_check_truncates_input() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/agenttrust/check")
        .match_body(Matcher::PartialJsonString(
            // The action_input_summary in the request body should be exactly 200 chars.
            format!(r#"{{"action_input_summary":"{}"}}"#, "x".repeat(200)),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"allowed": true}"#)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let long_input = "x".repeat(500);
    let result = client.actions().check(&ActionCheckRequest {
        agent_id: "agent-1".to_string(),
        tool_name: "tool_a".to_string(),
        tool_input_summary: long_input,
        ..Default::default()
    });

    assert!(result.is_ok());
    mock.assert();
}

// ---------------------------------------------------------------------------
// Telemetry report
// ---------------------------------------------------------------------------

#[test]
fn test_telemetry_report() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/telemetry/report")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"accepted": true, "events_processed": 2}"#)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let events = vec![
        TelemetryEvent {
            event_type: "tool_end".to_string(),
            tool_name: "search".to_string(),
            duration_ms: 100,
            success: true,
            error_type: None,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
        },
        TelemetryEvent {
            event_type: "tool_error".to_string(),
            tool_name: "analyze".to_string(),
            duration_ms: 50,
            success: false,
            error_type: Some("timeout".to_string()),
            timestamp: "2026-01-01T00:00:01Z".to_string(),
        },
    ];

    let result = client.telemetry().report("agent-1", "sess-1", &events);
    assert!(result.is_ok());
    mock.assert();
}

// ---------------------------------------------------------------------------
// Guard check / report / flush
// ---------------------------------------------------------------------------

#[test]
fn test_guard_check_allowed() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/agenttrust/check")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"allowed": true, "check_id": "chk-1", "confidence": 0.95, "guard_tier": "fast"}"#,
        )
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let guard = AgentTrustGuard::new(client, "agent-1");
    let result = guard.check("web_search", "query about AI");
    assert!(result.is_ok());
    mock.assert();
}

#[test]
fn test_guard_check_denied_block_on_deny() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/agenttrust/check")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"allowed": false, "reason": "capability not registered"}"#)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let guard = AgentTrustGuard::new(client, "agent-1"); // block_on_deny=true by default
    let result = guard.check("drop_database", "");
    assert!(result.is_err());
    match result.unwrap_err() {
        AgentTrustError::ActionDenied { message, .. } => {
            assert!(message.contains("denied"));
        }
        e => panic!("expected ActionDenied, got: {:?}", e),
    }
    mock.assert();
}

#[test]
fn test_guard_check_denied_no_block() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/agenttrust/check")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"allowed": false, "reason": "not registered"}"#)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let guard = AgentTrustGuard::builder(client, "agent-1")
        .block_on_deny(false)
        .build();

    let result = guard.check("dangerous_tool", "");
    assert!(result.is_ok()); // silently allowed
    mock.assert();
}

#[test]
fn test_guard_check_network_error_fail_closed() {
    let client = AgentTrustClient::builder()
        .base_url("http://127.0.0.1:1") // unreachable
        .timeout(std::time::Duration::from_millis(100))
        .build()
        .unwrap();

    let guard = AgentTrustGuard::new(client, "agent-1"); // fail_open=false by default
    let result = guard.check("web_search", "");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AgentTrustError::GuardianUnavailable { .. }
    ));
}

#[test]
fn test_guard_check_network_error_fail_open() {
    let client = AgentTrustClient::builder()
        .base_url("http://127.0.0.1:1") // unreachable
        .timeout(std::time::Duration::from_millis(100))
        .build()
        .unwrap();

    let guard = AgentTrustGuard::builder(client, "agent-1")
        .fail_open(true)
        .build();

    let result = guard.check("web_search", "");
    assert!(result.is_ok()); // fail-open allows it
}

#[test]
fn test_guard_report_buffers_events() {
    let mut srv = Server::new();

    // The Drop impl will try to flush the 2 buffered events, so expect exactly
    // 1 call (the auto-flush at drop). No flush should happen before drop since
    // we haven't hit the 10-event threshold.
    let _mock = srv
        .mock("POST", "/api/v1/telemetry/report")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"accepted": true, "events_processed": 2}"#)
        .expect_at_most(1)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let guard = AgentTrustGuard::new(client, "agent-1");
    guard.report("search", true, 120);
    guard.report("analyze", false, 50);

    // At this point, no flush has been triggered (buffer < 10).
    // The Drop impl will flush remaining events when guard goes out of scope.
}

#[test]
fn test_guard_report_auto_flush_at_10() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/telemetry/report")
        .expect(1) // Exactly one flush call with 10 events
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"accepted": true, "events_processed": 10}"#)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let guard = AgentTrustGuard::new(client, "agent-1");

    for i in 0..10 {
        guard.report(&format!("tool_{}", i), true, 10);
    }

    mock.assert();
}

#[test]
fn test_guard_flush_manual() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/telemetry/report")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"accepted": true, "events_processed": 2}"#)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let guard = AgentTrustGuard::new(client, "agent-1");
    guard.report("search", true, 120);
    guard.report("analyze", true, 200);

    let result = guard.flush();
    assert!(result.is_ok());
    mock.assert();
}

#[test]
fn test_guard_flush_empty() {
    let client = AgentTrustClient::builder()
        .base_url("http://unused:9999")
        .build()
        .unwrap();

    let guard = AgentTrustGuard::new(client, "agent-1");
    let result = guard.flush();
    assert!(result.is_ok()); // Empty buffer, no-op
}

#[test]
fn test_guard_custom_session_id() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/agenttrust/check")
        .match_body(Matcher::PartialJsonString(
            r#"{"session_id":"my-session-id"}"#.to_string(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"allowed": true}"#)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let guard = AgentTrustGuard::builder(client, "agent-1")
        .session_id("my-session-id")
        .build();

    assert_eq!(guard.session_id(), "my-session-id");

    let result = guard.check("tool_a", "");
    assert!(result.is_ok());
    mock.assert();
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

#[test]
fn test_error_authentication_401() {
    let mut srv = Server::new();

    let mock = srv
        .mock("GET", "/health")
        .with_status(401)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"invalid key"}"#)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let result = client.health();
    assert!(result.is_err());
    match result.unwrap_err() {
        AgentTrustError::Authentication { message, status } => {
            assert_eq!(message, "invalid key");
            assert_eq!(status, 401);
        }
        e => panic!("expected Authentication error, got: {:?}", e),
    }
    mock.assert();
}

#[test]
fn test_error_authorization_403() {
    let mut srv = Server::new();

    let mock = srv
        .mock("GET", "/health")
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"forbidden"}"#)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let result = client.health();
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AgentTrustError::Authorization { .. }
    ));
    mock.assert();
}

#[test]
fn test_error_server_500() {
    let mut srv = Server::new();

    let mock = srv
        .mock("GET", "/health")
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message":"internal error"}"#)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let result = client.health();
    assert!(result.is_err());
    match result.unwrap_err() {
        AgentTrustError::Api { status, code, .. } => {
            assert_eq!(status, 500);
            assert_eq!(code, "HTTP_500");
        }
        e => panic!("expected Api error, got: {:?}", e),
    }
    mock.assert();
}

#[test]
fn test_error_network() {
    let client = AgentTrustClient::builder()
        .base_url("http://127.0.0.1:1")
        .timeout(std::time::Duration::from_millis(100))
        .build()
        .unwrap();

    let result = client.health();
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AgentTrustError::Network(_)));
}

// ---------------------------------------------------------------------------
// Sessions API
// ---------------------------------------------------------------------------

#[test]
fn test_sessions_init() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/mcp/sessions/init")
        .match_body(Matcher::JsonString(
            r#"{"agent_id":"agent-123","server_id":"mcp-server-1"}"#.to_string(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "session_id": "sess-abc",
                "agent_id": "agent-123",
                "org_id": "org-1",
                "source": "mcp",
                "server_id": "mcp-server-1",
                "mode": "standard",
                "allowed_actions": ["web_search", "files:read"],
                "scope_ceiling": ["files:read"],
                "total_calls": 0,
                "read_calls": 0,
                "write_calls": 0,
                "denied_calls": 0,
                "created_at": "2026-03-01T00:00:00Z",
                "last_activity_at": "2026-03-01T00:00:00Z"
            }"#,
        )
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let session = client
        .sessions()
        .init_session("agent-123", "mcp-server-1")
        .unwrap();

    assert_eq!(session.session_id, "sess-abc");
    assert_eq!(session.agent_id, "agent-123");
    assert_eq!(session.org_id, "org-1");
    assert_eq!(session.source, "mcp");
    assert_eq!(session.server_id, "mcp-server-1");
    assert_eq!(session.mode, "standard");
    assert_eq!(session.allowed_actions, vec!["web_search", "files:read"]);
    assert_eq!(session.scope_ceiling, vec!["files:read"]);
    assert_eq!(session.total_calls, 0);
    mock.assert();
}

#[test]
fn test_sessions_get() {
    let mut srv = Server::new();

    let mock = srv
        .mock("GET", "/mcp/sessions/sess-abc")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "session_id": "sess-abc",
                "agent_id": "agent-123",
                "org_id": "org-1",
                "source": "mcp",
                "server_id": "mcp-server-1",
                "mode": "standard",
                "allowed_actions": [],
                "scope_ceiling": [],
                "total_calls": 5,
                "read_calls": 3,
                "write_calls": 1,
                "denied_calls": 1,
                "created_at": "2026-03-01T00:00:00Z",
                "last_activity_at": "2026-03-01T00:01:00Z"
            }"#,
        )
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let session = client.sessions().get_session("sess-abc").unwrap();
    assert_eq!(session.session_id, "sess-abc");
    assert_eq!(session.total_calls, 5);
    assert_eq!(session.read_calls, 3);
    assert_eq!(session.write_calls, 1);
    assert_eq!(session.denied_calls, 1);
    mock.assert();
}

// ---------------------------------------------------------------------------
// Approvals API
// ---------------------------------------------------------------------------

#[test]
fn test_approvals_approve() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/mcp/approvals/appr-123/approve")
        .match_body(Matcher::JsonString(
            r#"{"decided_by":"admin@example.com"}"#.to_string(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{}"#)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let result = client.approvals().approve("appr-123", "admin@example.com");
    assert!(result.is_ok());
    mock.assert();
}

#[test]
fn test_approvals_deny() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/mcp/approvals/appr-456/deny")
        .match_body(Matcher::JsonString(
            r#"{"decided_by":"security@example.com"}"#.to_string(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{}"#)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let result = client.approvals().deny("appr-456", "security@example.com");
    assert!(result.is_ok());
    mock.assert();
}

#[test]
fn test_approvals_get() {
    let mut srv = Server::new();

    let mock = srv
        .mock("GET", "/mcp/approvals/appr-789")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "id": "appr-789",
                "session_id": "sess-abc",
                "agent_id": "agent-123",
                "org_id": "org-1",
                "action_name": "delete_file",
                "action_effect": "write",
                "status": "pending",
                "created_at": "2026-03-01T00:00:00Z",
                "expires_at": "2026-03-01T01:00:00Z",
                "decided_by": null
            }"#,
        )
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let approval = client.approvals().get("appr-789").unwrap();
    assert_eq!(approval.id, "appr-789");
    assert_eq!(approval.session_id, "sess-abc");
    assert_eq!(approval.agent_id, "agent-123");
    assert_eq!(approval.action_name, "delete_file");
    assert_eq!(approval.action_effect, "write");
    assert_eq!(approval.status, "pending");
    assert!(approval.decided_by.is_none());
    mock.assert();
}

// ---------------------------------------------------------------------------
// Action check with action_effect and elevation fields
// ---------------------------------------------------------------------------

#[test]
fn test_actions_check_with_action_effect() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/agenttrust/check")
        .match_body(Matcher::PartialJsonString(
            r#"{"action_effect":"write"}"#.to_string(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"allowed": true, "check_id": "chk-2"}"#)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let result = client
        .actions()
        .check(&ActionCheckRequest {
            agent_id: "agent-1".to_string(),
            tool_name: "write_file".to_string(),
            action_effect: Some("write".to_string()),
            ..Default::default()
        })
        .unwrap();

    assert!(result.allowed);
    mock.assert();
}

#[test]
fn test_actions_check_returns_elevation_fields() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/agenttrust/check")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "allowed": false,
                "check_id": "chk-elev",
                "reason": "requires approval",
                "elevation_required": true,
                "approval_id": "appr-elev-1"
            }"#,
        )
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let result = client
        .actions()
        .check(&ActionCheckRequest {
            agent_id: "agent-1".to_string(),
            tool_name: "admin_action".to_string(),
            action_effect: Some("admin".to_string()),
            ..Default::default()
        })
        .unwrap();

    assert!(!result.allowed);
    assert_eq!(result.elevation_required, Some(true));
    assert_eq!(result.approval_id.as_deref(), Some("appr-elev-1"));
    mock.assert();
}

// ---------------------------------------------------------------------------
// Guard: elevation handling
// ---------------------------------------------------------------------------

#[test]
fn test_guard_check_elevation_required_block_on_deny() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/agenttrust/check")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "allowed": false,
                "elevation_required": true,
                "approval_id": "appr-guard-1",
                "reason": "needs approval"
            }"#,
        )
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let guard = AgentTrustGuard::new(client, "agent-1"); // block_on_deny=true by default
    let result = guard.check("dangerous_tool", "delete everything");
    assert!(result.is_err());
    match result.unwrap_err() {
        AgentTrustError::ElevationRequired {
            message,
            approval_id,
        } => {
            assert!(message.contains("dangerous_tool"));
            assert!(message.contains("elevated approval"));
            assert_eq!(approval_id, "appr-guard-1");
        }
        e => panic!("expected ElevationRequired, got: {:?}", e),
    }
    mock.assert();
}

#[test]
fn test_guard_check_elevation_required_no_block() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/agenttrust/check")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "allowed": false,
                "elevation_required": true,
                "approval_id": "appr-guard-2"
            }"#,
        )
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let guard = AgentTrustGuard::builder(client, "agent-1")
        .block_on_deny(false)
        .build();

    let result = guard.check("dangerous_tool", "");
    assert!(result.is_ok()); // silently allowed because block_on_deny=false
    mock.assert();
}

#[test]
fn test_guard_check_with_effect() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/agenttrust/check")
        .match_body(Matcher::PartialJsonString(
            r#"{"action_effect":"admin"}"#.to_string(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"allowed": true}"#)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let guard = AgentTrustGuard::new(client, "agent-1");
    let result = guard.check_with_effect("admin_tool", "reset server", "admin");
    assert!(result.is_ok());
    mock.assert();
}

#[test]
fn test_guard_default_action_effect() {
    let mut srv = Server::new();

    let mock = srv
        .mock("POST", "/api/v1/agenttrust/check")
        .match_body(Matcher::PartialJsonString(
            r#"{"action_effect":"write"}"#.to_string(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"allowed": true}"#)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .build()
        .unwrap();

    let guard = AgentTrustGuard::builder(client, "agent-1")
        .action_effect("write")
        .build();

    // Regular check() should use the default action_effect="write"
    let result = guard.check("write_tool", "update file");
    assert!(result.is_ok());
    mock.assert();
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

#[test]
fn test_api_key_header_sent() {
    let mut srv = Server::new();

    let mock = srv
        .mock("GET", "/health")
        .match_header("X-API-Key", "sk_test_abc")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"status":"healthy"}"#)
        .create();

    let client = AgentTrustClient::builder()
        .base_url(&srv.url())
        .api_key("sk_test_abc")
        .build()
        .unwrap();

    let result = client.health();
    assert!(result.is_ok());
    mock.assert();
}

#[cfg(test)]
mod from_env_coverage {
    use std::collections::HashMap;

    #[test]
    fn from_env_reads_agenttrust_url() {
        use crate::AgentTrustClient;
        let mut env = HashMap::new();
        env.insert("AGENTTRUST_URL".to_string(), "http://new:8080".to_string());
        env.insert("AGENTTRUST_API_KEY".to_string(), "sk_live_new".to_string());

        let client = AgentTrustClient::from_env_with(|k| env.get(k).cloned()).unwrap();
        assert!(
            client.base_url().contains("new"),
            "expected base URL from AGENTTRUST_URL; got {}",
            client.base_url()
        );
    }
}
