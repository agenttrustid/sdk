//! Data models for the AgentTrust ID SDK.
//!
//! All types use `serde` for JSON serialization/deserialization. Field names
//! naturally match the API's snake_case convention.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Public model types
// ---------------------------------------------------------------------------

/// A registered AI agent in the AgentTrust ID system.
///
/// The platform does not issue certificates; use [`crate::TokensAPI::issue`]
/// to mint opaque `at_` tokens for an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    /// Unique agent identifier.
    pub id: String,
    /// Human-readable agent name, unique within an organization.
    pub name: String,
    /// Organization that owns this agent.
    pub org_id: String,
    /// AI framework used (e.g., "openai", "langchain", "custom").
    pub framework: String,
    /// Agent's Ed25519 public key (PEM-encoded).
    #[serde(default)]
    pub public_key: String,
    /// Current status: "active", "suspended", or "revoked".
    pub status: String,
    /// Permissions the agent can request (e.g., "files:read").
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Arbitrary key-value metadata associated with the agent.
    #[serde(default)]
    pub metadata: serde_json::Value,
    /// When the agent was registered (ISO 8601).
    #[serde(default)]
    pub created_at: Option<String>,
    /// The agent's private key. Only populated when the platform supplies
    /// one during creation. Store this securely; it cannot be retrieved again.
    #[serde(default)]
    pub private_key: Option<String>,
}

/// An opaque agent token issued by ATI.
///
/// Tokens are random strings prefixed with `at_` (e.g. `at_xK3z9...`). They
/// are NOT JWTs — they have no signature and cannot be validated client-side.
/// To check a token, call [`crate::TokensAPI::introspect`], which sends it to
/// `POST /api/v1/agent-tokens/introspect`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    /// The opaque token string (e.g. `at_xK3z9...`) for use in
    /// `Authorization: Bearer` headers.
    pub token: String,
    /// Agent this token was issued to.
    pub agent_id: String,
    /// Permissions granted by this token.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Intended recipients/resources for this token.
    #[serde(default)]
    pub audience: Vec<String>,
    /// When the token was issued (ISO 8601).
    #[serde(default)]
    pub issued_at: Option<String>,
    /// When the token expires (ISO 8601).
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Unique token identifier.
    #[serde(default)]
    pub token_id: Option<String>,
}

/// Result of `POST /api/v1/agent-tokens/introspect`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionResult {
    /// Whether the token is currently usable.
    pub active: bool,
    /// Agent that owns the token.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Organization that owns the agent.
    #[serde(default)]
    pub org_id: Option<String>,
    /// Permissions granted by the token.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// When the token expires (ISO 8601).
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Human-readable explanation of the authorization decision.
    #[serde(default)]
    pub reasoning: Option<String>,
    /// Security check tier used ("fast", "spot", "deep").
    #[serde(default)]
    pub guard_tier: Option<String>,
    /// Confidence score of the authorization decision (0.0-1.0).
    #[serde(default)]
    pub confidence: Option<f64>,
    /// Time taken for the check in milliseconds.
    #[serde(default)]
    pub latency_ms: Option<i64>,
}

/// Deprecated alias for [`IntrospectionResult`].
///
/// The platform's verify endpoint was renamed to introspect when JWTs were
/// replaced with opaque tokens.
#[deprecated(note = "Use IntrospectionResult")]
pub type VerificationResult = IntrospectionResult;

/// The outcome of a pre-flight action authorization check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionCheckResult {
    /// Whether the action is authorized.
    pub allowed: bool,
    /// Unique identifier for this check.
    #[serde(default)]
    pub check_id: Option<String>,
    /// Confidence score (0.0-1.0).
    #[serde(default)]
    pub confidence: Option<f64>,
    /// Security check tier used ("fast", "spot", "deep").
    #[serde(default)]
    pub guard_tier: Option<String>,
    /// Time taken for the check in milliseconds.
    #[serde(default)]
    pub latency_ms: Option<i64>,
    /// Human-readable explanation of the decision.
    #[serde(default)]
    pub reason: Option<String>,
    /// Whether the action requires elevated approval.
    #[serde(default)]
    pub elevation_required: Option<bool>,
    /// The approval request ID when elevation is required.
    #[serde(default)]
    pub approval_id: Option<String>,
}

/// An MCP session representing a connected agent-server pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier.
    pub session_id: String,
    /// Agent that initiated the session.
    pub agent_id: String,
    /// Organization that owns the agent.
    pub org_id: String,
    /// How the session was initiated (e.g., "mcp", "api").
    #[serde(default)]
    pub source: String,
    /// The MCP server this session connects to.
    #[serde(default)]
    pub server_id: String,
    /// Session mode (e.g., "standard", "elevated").
    #[serde(default)]
    pub mode: String,
    /// Actions allowed in this session.
    #[serde(default)]
    pub allowed_actions: Vec<String>,
    /// Maximum scope ceiling for the session.
    #[serde(default)]
    pub scope_ceiling: Vec<String>,
    /// Total number of calls made in the session.
    #[serde(default)]
    pub total_calls: u64,
    /// Number of read calls made.
    #[serde(default)]
    pub read_calls: u64,
    /// Number of write calls made.
    #[serde(default)]
    pub write_calls: u64,
    /// Number of denied calls.
    #[serde(default)]
    pub denied_calls: u64,
    /// When the session was created (ISO 8601).
    #[serde(default)]
    pub created_at: Option<String>,
    /// When the session was last active (ISO 8601).
    #[serde(default)]
    pub last_activity_at: Option<String>,
}

/// Parameters for initializing a new MCP session.
#[derive(Debug, Serialize)]
pub struct InitSessionRequest {
    /// Agent that is initiating the session.
    pub agent_id: String,
    /// The MCP server to connect to.
    pub server_id: String,
}

/// Status of an approval request for an elevated action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequestStatus {
    /// Unique approval request identifier.
    pub id: String,
    /// Session in which the approval was requested.
    #[serde(default)]
    pub session_id: String,
    /// Agent that requested approval.
    #[serde(default)]
    pub agent_id: String,
    /// Organization that owns the agent.
    #[serde(default)]
    pub org_id: String,
    /// Name of the action requiring approval.
    #[serde(default)]
    pub action_name: String,
    /// Effect of the action (e.g., "read", "write", "admin").
    #[serde(default)]
    pub action_effect: String,
    /// Current status: "pending", "approved", "denied", "expired".
    #[serde(default)]
    pub status: String,
    /// When the approval request was created (ISO 8601).
    #[serde(default)]
    pub created_at: Option<String>,
    /// When the approval request expires (ISO 8601).
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Who made the approval/denial decision.
    #[serde(default)]
    pub decided_by: Option<String>,
}

/// A single telemetry event for agent behavior tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    /// Type of event (e.g., "tool_start", "tool_end", "tool_error").
    pub event_type: String,
    /// Name of the tool involved.
    pub tool_name: String,
    /// How long the operation took in milliseconds.
    #[serde(default)]
    pub duration_ms: u64,
    /// Whether the operation succeeded.
    #[serde(default)]
    pub success: bool,
    /// Error class name if the operation failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_type: Option<String>,
    /// ISO 8601 timestamp of the event.
    #[serde(default)]
    pub timestamp: String,
}

/// Response from the health check endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Service health status ("healthy", "degraded", "unhealthy").
    pub status: String,
    /// Name of the service responding.
    #[serde(default)]
    pub service: Option<String>,
    /// Service version.
    #[serde(default)]
    pub version: Option<String>,
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// Parameters for creating a new agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAgentRequest {
    /// Agent name (required). Must be unique within the organization.
    pub name: String,
    /// AI framework (default: "custom").
    #[serde(default = "default_framework")]
    pub framework: String,
    /// Permissions the agent can request.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Arbitrary metadata key-value pairs.
    #[serde(default = "default_metadata")]
    pub metadata: serde_json::Value,
    /// Organization ID (optional, uses default org if empty).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    /// Bring-your-own Ed25519 public key (PKIX/SPKI PEM). When omitted, the SDK
    /// generates a keypair locally at create time and registers only the public
    /// half; the private key is returned on the resulting [`Agent`] and never
    /// sent to the platform.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

fn default_framework() -> String {
    "custom".to_string()
}

fn default_metadata() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

/// Parameters for issuing a new capability token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueTokenRequest {
    /// Agent requesting the token (required).
    pub agent_id: String,
    /// Permissions to include in the token (required).
    #[serde(rename = "scopes")]
    pub scope: Vec<String>,
    /// Target resources for the token.
    #[serde(default, skip_serializing)]
    pub audience: Vec<String>,
    /// Token time-to-live in seconds (default: 300).
    #[serde(default = "default_ttl")]
    pub ttl: u64,
}

fn default_ttl() -> u64 {
    300
}

/// Parameters for `POST /api/v1/agent-tokens/introspect`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectTokenRequest {
    /// Opaque agent token string (e.g. `at_...`) to introspect (required).
    pub token: String,
    /// Resource being accessed (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Scopes that must be present in the token.
    #[serde(default)]
    pub required_scopes: Vec<String>,
}

/// Deprecated alias for [`IntrospectTokenRequest`].
#[deprecated(note = "Use IntrospectTokenRequest")]
pub type VerifyTokenRequest = IntrospectTokenRequest;

/// Parameters for revoking a token.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct RevokeTokenRequest {
    pub token: String,
    pub reason: String,
}

/// Parameters for revoking an agent.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct RevokeAgentRequest {
    pub reason: String,
}

/// Parameters for a pre-flight action check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionCheckRequest {
    /// Agent requesting the action (required).
    pub agent_id: String,
    /// Type of action being performed (default: "tool_call").
    #[serde(default = "default_action")]
    pub action: String,
    /// Name of the tool being invoked (required).
    pub tool_name: String,
    /// Truncated summary of the tool input (max 200 chars, for privacy).
    #[serde(default)]
    pub tool_input_summary: String,
    /// Current session ID for event correlation.
    #[serde(default)]
    pub session_id: String,
    /// The effect of the action (e.g., "read", "write", "admin").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_effect: Option<String>,
}

fn default_action() -> String {
    "tool_call".to_string()
}

/// Parameters for reporting telemetry events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryReportRequest {
    /// Agent that generated the events.
    pub agent_id: String,
    /// Session ID for event correlation.
    pub session_id: String,
    /// List of telemetry events to report.
    pub events: Vec<TelemetryEvent>,
}

// ---------------------------------------------------------------------------
// Wire-format types for parsing API responses
// ---------------------------------------------------------------------------

/// The API may wrap agent creation responses in `{"agent": {...}}`.
#[derive(Debug, Deserialize)]
pub(crate) struct CreateAgentResponse {
    // Flat fields (when API returns agent data at the top level)
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub org_id: Option<String>,
    #[serde(default)]
    pub framework: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub capabilities: Option<Vec<String>>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,

    // Nested response format
    #[serde(default)]
    pub agent: Option<AgentData>,
}

/// Nested agent object within API responses.
#[derive(Debug, Deserialize)]
pub(crate) struct AgentData {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub org_id: String,
    #[serde(default)]
    pub framework: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub metadata: serde_json::Value,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
}

/// Wire format for the list-agents endpoint.
#[derive(Debug, Deserialize)]
pub(crate) struct AgentListResponse {
    #[serde(default)]
    pub agents: Vec<AgentData>,
}

/// Wire format for the token-issue endpoint.
#[derive(Debug, Deserialize)]
pub(crate) struct IssueTokenResponse {
    #[serde(default)]
    pub token: Option<String>,
    /// Alternative field name the server may use.
    #[serde(default)]
    pub agent_token: Option<String>,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    pub scope: Option<Vec<String>>,
    #[serde(default)]
    pub audience: Vec<String>,
    #[serde(default)]
    pub issued_at: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub token_id: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
}

/// Wire format for the telemetry report endpoint.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(crate) struct TelemetryReportResponse {
    #[serde(default)]
    pub accepted: bool,
    #[serde(default)]
    pub events_processed: usize,
}

/// API error response body.
#[derive(Debug, Deserialize)]
pub(crate) struct ErrorResponse {
    #[serde(default)]
    pub message: String,
}

// ---------------------------------------------------------------------------
// Agent Card models (A2A v1.0 discovery)
// ---------------------------------------------------------------------------

/// URI of the ATI trust extension carried in `capabilities.extensions`.
pub const ATI_TRUST_EXTENSION_URI: &str = "https://agenttrust.id/ext/trust/v1";

/// An A2A v1.0-compatible agent card describing an agent's identity and
/// capabilities.
///
/// This struct is **deserialized** from the JSON the server publishes at
/// `/a2a/agents/{id}/agent.json`. Every field carries a `serde` default so that
/// both a full v1.0 card and an older/legacy card (or a card missing newly
/// added fields) parse without error.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentCard {
    /// Agent display name.
    #[serde(default)]
    pub name: String,
    /// Human-readable description of the agent.
    #[serde(default)]
    pub description: String,
    /// Card version.
    #[serde(default)]
    pub version: String,
    /// A2A v1.0 transport/interface descriptors. The first entry is the
    /// agent's primary callable endpoint.
    #[serde(rename = "supportedInterfaces", default)]
    pub supported_interfaces: Vec<AgentInterface>,
    /// Provider/organization metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<Provider>,
    /// Supported capabilities, including extensions (where ATI trust data now
    /// lives).
    #[serde(default)]
    pub capabilities: Capabilities,
    /// Named security schemes (A2A v1.0), keyed by scheme name.
    #[serde(
        rename = "securitySchemes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub security_schemes: Option<HashMap<String, SecurityScheme>>,
    /// Default input MIME modes the agent accepts.
    #[serde(rename = "defaultInputModes", default)]
    pub default_input_modes: Vec<String>,
    /// Default output MIME modes the agent produces.
    #[serde(rename = "defaultOutputModes", default)]
    pub default_output_modes: Vec<String>,
    /// Skills the agent advertises.
    #[serde(default)]
    pub skills: Vec<AgentCardSkill>,
    /// JWS signatures over the card (A2A v1.0).
    #[serde(default)]
    pub signatures: Vec<AgentCardSignature>,
    /// Optional documentation URL.
    #[serde(
        rename = "documentationUrl",
        default,
        alias = "documentation_url",
        skip_serializing_if = "Option::is_none"
    )]
    pub documentation_url: Option<String>,
    /// Optional icon URL.
    #[serde(
        rename = "iconUrl",
        default,
        alias = "icon_url",
        skip_serializing_if = "Option::is_none"
    )]
    pub icon_url: Option<String>,
    /// Legacy top-level URL (pre-v1.0). Kept optional with a default so legacy
    /// cards still parse and `primary_url()` can fall back to it. v1.0 cards
    /// carry the URL inside [`supported_interfaces`] instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl AgentCard {
    /// The agent's primary callable URL.
    ///
    /// Prefers the first entry of [`supported_interfaces`](Self::supported_interfaces)
    /// (A2A v1.0); falls back to the legacy top-level [`url`](Self::url).
    pub fn primary_url(&self) -> Option<&str> {
        self.supported_interfaces
            .first()
            .map(|i| i.url.as_str())
            .or(self.url.as_deref())
    }

    /// The ATI trust score advertised by this card.
    ///
    /// Reads `capabilities.extensions` for the extension whose `uri` equals
    /// [`ATI_TRUST_EXTENSION_URI`] and returns its `params["ati_trust_score"]`
    /// as an `f64`. Returns `0.0` when the extension or field is absent.
    pub fn trust_score(&self) -> f64 {
        self.capabilities
            .extensions
            .iter()
            .find(|e| e.uri == ATI_TRUST_EXTENSION_URI)
            .and_then(|e| e.params.as_ref())
            .and_then(|p| p.get("ati_trust_score"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0)
    }

    /// The agent's registered Ed25519 public key (PKIX/SPKI PEM) from the card's
    /// trust extension (`ati_agent_key`), or `None` if the card predates the
    /// proof-of-possession binding.
    ///
    /// Pair this with a challenge (`POST /api/v1/agents/{id}/challenge`) to prove
    /// the card holder controls the key the card claims. Verify the card's
    /// platform JWS first — that is what makes this key authoritative.
    pub fn agent_public_key_pem(&self) -> Option<String> {
        use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
        use ed25519_dalek::pkcs8::spki::EncodePublicKey;

        let jwk = self
            .capabilities
            .extensions
            .iter()
            .find(|e| e.uri == ATI_TRUST_EXTENSION_URI)
            .and_then(|e| e.params.as_ref())
            .and_then(|p| p.get("ati_agent_key"))?;
        if jwk.get("kty").and_then(|v| v.as_str()) != Some("OKP")
            || jwk.get("crv").and_then(|v| v.as_str()) != Some("Ed25519")
        {
            return None;
        }
        let x = jwk.get("x").and_then(|v| v.as_str())?;
        let raw = base64url_decode(x)?;
        let bytes: [u8; 32] = raw.try_into().ok()?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok()?;
        vk.to_public_key_pem(LineEnding::LF).ok()
    }
}

/// Decode an unpadded base64url string (RFC 4648 §5). Returns `None` on any
/// non-alphabet byte. Trailing partial bits are discarded (canonical form).
fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut lut = [255u8; 256];
    for (i, &c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        .iter()
        .enumerate()
    {
        lut[c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        let v = lut[c as usize];
        if v == 255 {
            return None;
        }
        buf = (buf << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// An A2A v1.0 transport interface descriptor.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentInterface {
    /// Endpoint URL for this interface.
    #[serde(default)]
    pub url: String,
    /// Transport/protocol binding (e.g., `JSONRPC`, `GRPC`, `HTTP+JSON`).
    #[serde(rename = "protocolBinding", default, alias = "protocol_binding")]
    pub protocol_binding: String,
    /// Protocol version advertised by this interface.
    #[serde(rename = "protocolVersion", default, alias = "protocol_version")]
    pub protocol_version: String,
    /// Optional tenant identifier scoping this interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

/// Provider section of an [`AgentCard`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Provider {
    /// Organization name.
    #[serde(default)]
    pub organization: String,
    /// Organization URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Capabilities advertised on an [`AgentCard`] (A2A v1.0).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    /// Whether the agent supports streaming responses.
    #[serde(default)]
    pub streaming: bool,
    /// Whether the agent supports push notifications.
    #[serde(rename = "pushNotifications", default, alias = "push_notifications")]
    pub push_notifications: bool,
    /// A2A extensions. ATI trust data is carried here under
    /// [`ATI_TRUST_EXTENSION_URI`].
    #[serde(default)]
    pub extensions: Vec<AgentExtension>,
    /// Whether the agent exposes an extended (authenticated) agent card.
    #[serde(
        rename = "extendedAgentCard",
        default,
        alias = "extended_agent_card",
        skip_serializing_if = "Option::is_none"
    )]
    pub extended_agent_card: Option<bool>,
}

/// An A2A v1.0 capability extension entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentExtension {
    /// Extension URI identifying the extension type.
    #[serde(default)]
    pub uri: String,
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether the extension is required to interact with the agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    /// Extension-specific parameters (free-form JSON).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// A named security scheme (A2A v1.0).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityScheme {
    /// Scheme type (e.g., `http`, `apiKey`, `oauth2`).
    #[serde(rename = "type", default)]
    pub r#type: String,
    /// HTTP scheme (e.g., `bearer`) when `type == "http"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
}

/// A skill listed on an [`AgentCard`] (A2A v1.0).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentCardSkill {
    /// Skill identifier.
    #[serde(default)]
    pub id: String,
    /// Human-readable skill name.
    #[serde(default)]
    pub name: String,
    /// Description.
    #[serde(default)]
    pub description: String,
    /// Free-form tags describing the skill.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Example prompts the skill handles.
    #[serde(default)]
    pub examples: Vec<String>,
    /// Input MIME modes accepted by the skill.
    #[serde(rename = "inputModes", default, alias = "input_modes")]
    pub input_modes: Vec<String>,
    /// Output MIME modes produced by the skill.
    #[serde(rename = "outputModes", default, alias = "output_modes")]
    pub output_modes: Vec<String>,
}

/// A JWS signature over an [`AgentCard`] (A2A v1.0).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentCardSignature {
    /// Base64url-encoded protected JWS header.
    #[serde(default)]
    pub protected: String,
    /// Base64url-encoded signature.
    #[serde(default)]
    pub signature: String,
    /// Optional unprotected JWS header (free-form JSON).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// A2A models
// ---------------------------------------------------------------------------

/// Represents an agent-to-agent task.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct A2ATask {
    /// Task identifier.
    #[serde(default)]
    pub id: String,
    /// Source (caller) agent.
    #[serde(default, alias = "sourceAgentId")]
    pub source_agent_id: String,
    /// Target (callee) agent.
    #[serde(default, alias = "targetAgentId")]
    pub target_agent_id: String,
    /// Current status (e.g., `pending`, `running`, `completed`, `failed`).
    #[serde(default)]
    pub status: String,
    /// Initial message sent to the target agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<serde_json::Value>,
    /// Artifacts produced by the task.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<serde_json::Value>,
    /// Arbitrary task metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// ISO 8601 creation time.
    #[serde(default, alias = "createdAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// ISO 8601 last update time.
    #[serde(default, alias = "updatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// Parameters for sending a new A2A task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendTaskRequest {
    /// Source agent ID.
    pub source_agent_id: String,
    /// Target agent ID.
    pub target_agent_id: String,
    /// JSON-RPC compatible message payload.
    pub message: serde_json::Value,
}

/// An A2A v1.0 `Task` returned by `message/send`.
///
/// Deserialized from the JSON-RPC result of `message/send` (and compatible with
/// `tasks/get`). All fields default so partial server responses still parse.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct V1Task {
    /// Task identifier.
    #[serde(default)]
    pub id: String,
    /// Context (conversation) identifier grouping related messages.
    #[serde(rename = "contextId", default, alias = "context_id")]
    pub context_id: String,
    /// Current task status.
    #[serde(default)]
    pub status: V1TaskStatus,
    /// Message/turn history, when the server returns it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<serde_json::Value>>,
    /// Artifacts produced by the task, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<serde_json::Value>>,
}

/// Status block of a [`V1Task`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct V1TaskStatus {
    /// Lifecycle state (e.g., `submitted`, `working`, `completed`, `failed`).
    #[serde(default)]
    pub state: String,
    /// ISO 8601 timestamp of the status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

// ---------------------------------------------------------------------------
// MCP models
// ---------------------------------------------------------------------------

/// A registered MCP server.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MCPServer {
    /// Server identifier.
    #[serde(default)]
    pub id: String,
    /// Display name.
    #[serde(default)]
    pub name: String,
    /// Server URL (e.g., `https://mcp.example.com`).
    #[serde(default)]
    pub url: String,
    /// Server-supported capabilities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    /// Owning organization.
    #[serde(default, alias = "orgId", skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    /// Creation time (ISO 8601).
    #[serde(default, alias = "createdAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// Parameters for registering a new MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterMCPServerRequest {
    /// Display name.
    pub name: String,
    /// Server URL.
    pub url: String,
    /// Capabilities advertised by the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Delegation models
// ---------------------------------------------------------------------------

/// A capability delegation between two agents.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Delegation {
    /// Delegation identifier.
    #[serde(default)]
    pub id: String,
    /// Granting agent.
    #[serde(default, alias = "fromAgentId")]
    pub from_agent_id: String,
    /// Receiving agent.
    #[serde(default, alias = "toAgentId")]
    pub to_agent_id: String,
    /// Owning organization (optional).
    #[serde(default, alias = "orgId", skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    /// Granted scope.
    #[serde(default)]
    pub scope: Vec<String>,
    /// Optional restrictions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restrictions: Option<serde_json::Value>,
    /// Chain of delegations leading to this one.
    #[serde(
        default,
        alias = "delegationChain",
        skip_serializing_if = "Option::is_none"
    )]
    pub delegation_chain: Option<Vec<String>>,
    /// Expiration time (ISO 8601).
    #[serde(default, alias = "expiresAt")]
    pub expires_at: String,
    /// Revocation time, if revoked (ISO 8601).
    #[serde(default, alias = "revokedAt", skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    /// Creation time (ISO 8601).
    #[serde(default, alias = "createdAt")]
    pub created_at: String,
}

/// Parameters for creating a delegation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDelegationRequest {
    /// Granting agent.
    pub from_agent_id: String,
    /// Receiving agent.
    pub to_agent_id: String,
    /// Granted scope.
    pub scope: Vec<String>,
    /// Time-to-live in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    /// Optional restrictions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restrictions: Option<serde_json::Value>,
    /// Parent delegation if this is a re-delegation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_delegation_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Federation models
// ---------------------------------------------------------------------------

/// An OIDC federation provider registered with ATI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FederationProvider {
    /// Provider identifier.
    #[serde(default)]
    pub id: String,
    /// Owning organization.
    #[serde(default, alias = "orgId")]
    pub org_id: String,
    /// OIDC issuer URL.
    #[serde(default)]
    pub issuer: String,
    /// Display name.
    #[serde(default)]
    pub name: String,
    /// JWKS endpoint.
    #[serde(default, alias = "jwksUri")]
    pub jwks_uri: String,
    /// Authorization endpoint (optional).
    #[serde(
        default,
        alias = "authorizationEndpoint",
        skip_serializing_if = "Option::is_none"
    )]
    pub authorization_endpoint: Option<String>,
    /// Token endpoint (optional).
    #[serde(
        default,
        alias = "tokenEndpoint",
        skip_serializing_if = "Option::is_none"
    )]
    pub token_endpoint: Option<String>,
    /// Trust level (e.g., `standard`, `high`).
    #[serde(default, alias = "trustLevel")]
    pub trust_level: String,
    /// Status (`active`, `disabled`).
    #[serde(default)]
    pub status: String,
    /// Creation time (ISO 8601).
    #[serde(default, alias = "createdAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Last update time (ISO 8601).
    #[serde(default, alias = "updatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// Parameters for registering an OIDC federation provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterFederationProviderRequest {
    /// OIDC issuer URL.
    pub issuer: String,
    /// Display name.
    pub name: String,
    /// Trust level (default `standard`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_level: Option<String>,
}

/// Parameters for verifying a federated token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyFederatedTokenRequest {
    /// Token to verify.
    pub token: String,
    /// Optional issuer hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_hint: Option<String>,
}

/// Result of verifying a federated token.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerifyFederatedTokenResult {
    /// Whether the token is valid.
    pub valid: bool,
    /// Mapped agent ID, if the token authenticates a known agent.
    #[serde(default, alias = "agentId", skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Issuer of the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Token expiration (ISO 8601).
    #[serde(default, alias = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Reason if invalid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for issuing a federated ID token.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IssueFederatedIDTokenRequest {
    /// Optional audience.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Optional nonce.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Optional scopes for the opaque federation token.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// Optional TTL in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
}

/// Result of issuing a federated ID token.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IssueFederatedIDTokenResult {
    /// The issued opaque federation token. Retains the historical field name
    /// for source compatibility.
    #[serde(default, alias = "idToken", alias = "token")]
    pub id_token: String,
    /// Lifetime in seconds.
    #[serde(default, alias = "expiresIn")]
    pub expires_in: u64,
}

// ---------------------------------------------------------------------------
// Streaming / SIEM models
// ---------------------------------------------------------------------------

/// A configured SIEM streaming destination.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SIEMDestination {
    /// Destination identifier.
    #[serde(default)]
    pub id: String,
    /// Owning organization.
    #[serde(default, alias = "orgId", skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    /// Display name.
    #[serde(default)]
    pub name: String,
    /// Destination type (`splunk`, `datadog`, `webhook`, etc.).
    #[serde(default, alias = "destinationType")]
    pub destination_type: String,
    /// Endpoint URL events are POSTed to.
    #[serde(default, alias = "endpointUrl")]
    pub endpoint_url: String,
    /// Optional auth bearer token.
    #[serde(default, alias = "authToken", skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    /// Whether the destination is currently active.
    #[serde(default, alias = "isActive")]
    pub is_active: bool,
    /// Batch size before flush.
    #[serde(default, alias = "batchSize")]
    pub batch_size: u32,
    /// Flush interval in seconds.
    #[serde(default, alias = "flushIntervalSeconds")]
    pub flush_interval_seconds: u32,
    /// Optional event-type filter.
    #[serde(
        default,
        alias = "filterEventTypes",
        skip_serializing_if = "Option::is_none"
    )]
    pub filter_event_types: Option<Vec<String>>,
    /// Creation time (ISO 8601).
    #[serde(default, alias = "createdAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Last update time (ISO 8601).
    #[serde(default, alias = "updatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// Parameters for creating a SIEM destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSIEMDestinationRequest {
    /// Display name.
    pub name: String,
    /// Destination type.
    pub destination_type: String,
    /// Endpoint URL.
    pub endpoint_url: String,
    /// Optional auth bearer token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    /// Optional batch size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_size: Option<u32>,
    /// Optional flush interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flush_interval_seconds: Option<u32>,
    /// Optional event-type filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_event_types: Option<Vec<String>>,
}

/// Parameters for updating a SIEM destination.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateSIEMDestinationRequest {
    /// New display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// New endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,
    /// New auth token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    /// New active flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
    /// New batch size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_size: Option<u32>,
    /// New flush interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flush_interval_seconds: Option<u32>,
    /// New event-type filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_event_types: Option<Vec<String>>,
}

/// A delivery attempt to a SIEM destination.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SIEMDeliveryRecord {
    /// Record identifier.
    #[serde(default)]
    pub id: String,
    /// Destination this delivery targeted.
    #[serde(default, alias = "destinationId")]
    pub destination_id: String,
    /// Number of events in the batch.
    #[serde(default, alias = "batchSize")]
    pub batch_size: u32,
    /// Delivery status (`success`, `failed`).
    #[serde(default)]
    pub status: String,
    /// HTTP status code returned by the endpoint.
    #[serde(default, alias = "statusCode", skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u32>,
    /// Error message if delivery failed.
    #[serde(
        default,
        alias = "errorMessage",
        skip_serializing_if = "Option::is_none"
    )]
    pub error_message: Option<String>,
    /// Time the batch was delivered (ISO 8601).
    #[serde(default, alias = "deliveredAt")]
    pub delivered_at: String,
}

// ---------------------------------------------------------------------------
// WIMSE models
// ---------------------------------------------------------------------------

/// Parameters for issuing a WIMSE workload identity token.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IssueWIMSETokenRequest {
    /// Agent the token is issued to.
    pub agent_id: String,
    /// Optional service name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    /// Optional environment (e.g., `prod`, `staging`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Optional TTL in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    /// Optional audience entries the token is intended for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<String>>,
    /// Proof-of-possession over a server challenge. Prefer
    /// [`crate::wimse::Wimse::issue_token_with_proof`], which populates this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<PoPProof>,
}

/// A proof-of-possession: an Ed25519 signature over a server-issued challenge
/// nonce, proving the agent holds the private key matching its registered public
/// key. A valid proof binds the issued token to that key via `cnf.jkt`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoPProof {
    /// The single-use challenge nonce.
    pub nonce: String,
    /// Signing time in unix seconds.
    pub ts: i64,
    /// Ed25519 signature, base64url without padding.
    pub signature: String,
}

/// Server reply to a proof-of-possession challenge.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// The single-use challenge nonce.
    #[serde(default)]
    pub nonce: String,
    /// When the nonce expires (ISO 8601).
    #[serde(default)]
    pub expires_at: String,
}

/// Result of issuing a WIMSE workload identity token.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WIMSETokenResponse {
    /// The signed JWT.
    #[serde(default)]
    pub token: String,
    /// Workload SPIFFE-style ID.
    #[serde(default)]
    pub workload_id: String,
    /// Trust domain.
    #[serde(default)]
    pub trust_domain: String,
    /// Expiration (ISO 8601).
    #[serde(default)]
    pub expires_at: String,
}

/// Parameters for verifying a WIMSE workload identity token.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerifyWIMSETokenRequest {
    /// Token to verify.
    pub token: String,
    /// Optional trust-domain filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain_filter: Option<String>,
}

/// Result of verifying a WIMSE workload identity token.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerifyWIMSETokenResponse {
    /// Whether the token is valid.
    #[serde(default)]
    pub valid: bool,
    /// Mapped agent ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Workload SPIFFE-style ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,
    /// Trust domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,
    /// Capabilities granted to the workload.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Reason if invalid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

impl CreateAgentResponse {
    /// Convert the wire-format response into a public `Agent`.
    pub(crate) fn into_agent(self) -> Agent {
        if let Some(ad) = self.agent {
            // Nested response: {"agent": {...}}
            Agent {
                id: ad.id,
                name: ad.name,
                org_id: ad.org_id,
                framework: if ad.framework.is_empty() {
                    "custom".to_string()
                } else {
                    ad.framework
                },
                public_key: ad.public_key,
                status: if ad.status.is_empty() {
                    "active".to_string()
                } else {
                    ad.status
                },
                capabilities: ad.capabilities,
                metadata: ad.metadata,
                created_at: ad.created_at,
                private_key: ad.private_key,
            }
        } else {
            // Flat response: fields at top level
            Agent {
                id: self.id.unwrap_or_default(),
                name: self.name.unwrap_or_default(),
                org_id: self.org_id.unwrap_or_default(),
                framework: self.framework.unwrap_or_else(|| "custom".to_string()),
                public_key: self.public_key.unwrap_or_default(),
                status: self.status.unwrap_or_else(|| "active".to_string()),
                capabilities: self.capabilities.unwrap_or_default(),
                metadata: self.metadata.unwrap_or_else(default_metadata),
                created_at: self.created_at,
                private_key: self.private_key,
            }
        }
    }
}

impl AgentData {
    /// Convert wire-format agent data to a public `Agent`.
    pub(crate) fn into_agent(self) -> Agent {
        Agent {
            id: self.id,
            name: self.name,
            org_id: self.org_id,
            framework: if self.framework.is_empty() {
                "custom".to_string()
            } else {
                self.framework
            },
            public_key: self.public_key,
            status: if self.status.is_empty() {
                "active".to_string()
            } else {
                self.status
            },
            capabilities: self.capabilities,
            metadata: self.metadata,
            created_at: self.created_at,
            private_key: self.private_key,
        }
    }
}

impl IssueTokenResponse {
    /// Convert wire-format token response to a public `Token`.
    pub(crate) fn into_token(self) -> Token {
        let tok = self.token.unwrap_or_default();
        let tok = if tok.is_empty() {
            self.agent_token.unwrap_or_default()
        } else {
            tok
        };

        let scopes = self.scopes.unwrap_or_default();
        let scopes = if scopes.is_empty() {
            self.scope.unwrap_or_default()
        } else {
            scopes
        };

        let token_id = self.token_id.or(self.id);

        Token {
            token: tok,
            agent_id: self.agent_id,
            scopes,
            audience: self.audience,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            token_id,
        }
    }
}

#[cfg(test)]
mod card_pop_tests {
    use super::*;
    use crate::keys::{generate_agent_key, parse_public_key};
    use crate::wimse::base64url_no_pad;

    #[test]
    fn agent_public_key_pem_roundtrips() {
        let kp = generate_agent_key().unwrap();
        let vk = parse_public_key(&kp.public_key_pem).unwrap();
        let x = base64url_no_pad(vk.as_bytes());
        let json = format!(
            r#"{{"name":"a","capabilities":{{"extensions":[{{"uri":"https://agenttrust.id/ext/trust/v1","params":{{"ati_agent_key":{{"kty":"OKP","crv":"Ed25519","x":"{x}"}}}}}}]}}}}"#
        );
        let card: AgentCard = serde_json::from_str(&json).unwrap();
        let pem = card.agent_public_key_pem().expect("expected an embedded key");
        assert_eq!(pem.trim(), kp.public_key_pem.trim());
    }

    #[test]
    fn agent_public_key_pem_absent_is_none() {
        // No trust extension at all.
        let card: AgentCard = serde_json::from_str(r#"{"name":"a"}"#).unwrap();
        assert!(card.agent_public_key_pem().is_none());
        // Trust extension present but no ati_agent_key.
        let legacy: AgentCard = serde_json::from_str(
            r#"{"name":"a","capabilities":{"extensions":[{"uri":"https://agenttrust.id/ext/trust/v1","params":{"ati_trust_score":0.5}}]}}"#,
        )
        .unwrap();
        assert!(legacy.agent_public_key_pem().is_none());
    }

    #[test]
    fn agent_public_key_pem_malformed_is_none() {
        let card: AgentCard = serde_json::from_str(
            r#"{"name":"a","capabilities":{"extensions":[{"uri":"https://agenttrust.id/ext/trust/v1","params":{"ati_agent_key":{"kty":"OKP","crv":"Ed25519","x":"not base64!!"}}}]}}"#,
        )
        .unwrap();
        assert!(card.agent_public_key_pem().is_none());
    }
}
