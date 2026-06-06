//! # AgentTrust SDK
//!
//! The AgentTrust SDK provides authentication and authorization for AI agents.
//! It enables secure, auditable agent operations through identity management,
//! capability tokens, pre-flight action checks, and telemetry reporting.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use agenttrustid::{AgentTrustClient, CreateAgentRequest, IssueTokenRequest, AgentTrustGuard};
//!
//! // Create a client
//! let client = AgentTrustClient::builder()
//!     .base_url("http://localhost:8080")
//!     .api_key("sk_live_xxx")
//!     .build()
//!     .unwrap();
//!
//! // Register an agent
//! let agent = client.agents().create(&CreateAgentRequest {
//!     name: "my-assistant".to_string(),
//!     framework: "langchain".to_string(),
//!     capabilities: vec!["files:read".to_string()],
//!     ..Default::default()
//! }).unwrap();
//!
//! // Issue an opaque agent token (prefix `at_`)
//! let token = client.tokens().issue(&IssueTokenRequest {
//!     agent_id: agent.id.clone(),
//!     scope: vec!["files:read".to_string()],
//!     audience: vec!["mcp://filesystem".to_string()],
//!     ttl: 300,
//! }).unwrap();
//!
//! println!("Token: {}", token.token);
//! ```
//!
//! ## Guard Pattern
//!
//! The [`AgentTrustGuard`] provides a high-level wrapper for agents using raw
//! OpenAI/Anthropic SDKs:
//!
//! ```rust,no_run
//! use agenttrustid::{AgentTrustClient, AgentTrustGuard};
//!
//! let client = AgentTrustClient::from_env().unwrap();
//! let guard = AgentTrustGuard::new(client, "agent-123");
//!
//! // Before tool calls
//! guard.check("web_search", "AI news").unwrap();
//!
//! // After tool calls
//! guard.report("web_search", true, 1200);
//!
//! // Telemetry auto-flushed on drop
//! ```

pub mod a2a;
pub mod actions;
pub mod agentcards;
pub mod agents;
pub mod approvals;
pub mod client;
pub mod delegations;
pub mod error;
pub mod federation;
pub mod guard;
pub mod mcp;
pub mod models;
pub mod sessions;
pub mod streaming;
pub mod telemetry;
pub mod tokens;
pub mod wimse;

#[cfg(test)]
mod tests;

// Public re-exports for convenient top-level access.
pub use a2a::A2A;
pub use agentcards::AgentCards;
pub use approvals::ApprovalsAPI;
pub use client::{AgentTrustClient, AgentTrustClientBuilder};
pub use delegations::Delegations;
pub use error::{AgentTrustError, Result};
pub use federation::Federation;
pub use guard::{AgentTrustGuard, AgentTrustGuardBuilder};

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------






pub use mcp::Mcp;
pub use models::{
    A2ATask, ActionCheckRequest, ActionCheckResult, Agent, AgentCard, AgentCardSignature,
    AgentCardSkill, AgentExtension, AgentInterface, ApprovalRequestStatus, Capabilities,
    CreateAgentRequest, CreateDelegationRequest, CreateSIEMDestinationRequest, Delegation,
    FederationProvider, HealthResponse, InitSessionRequest, IntrospectTokenRequest,
    IntrospectionResult, IssueFederatedIDTokenRequest, IssueFederatedIDTokenResult,
    IssueTokenRequest, IssueWIMSETokenRequest, MCPServer, Provider,
    RegisterFederationProviderRequest, RegisterMCPServerRequest, SIEMDeliveryRecord,
    SIEMDestination, SecurityScheme, SendTaskRequest, Session, TelemetryEvent,
    TelemetryReportRequest, Token, UpdateSIEMDestinationRequest, V1Task, V1TaskStatus,
    VerifyFederatedTokenRequest, VerifyFederatedTokenResult, VerifyWIMSETokenRequest,
    VerifyWIMSETokenResponse, WIMSETokenResponse, ATI_TRUST_EXTENSION_URI,
};
pub use sessions::SessionsAPI;
pub use streaming::{StreamFilter, Streaming};
pub use wimse::Wimse;
