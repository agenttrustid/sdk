package agenttrust

import "time"

// Agent represents a registered AI agent in the AgentTrust ID system.
type Agent struct {
	// ID is the unique agent identifier.
	ID string `json:"id"`
	// Name is the human-readable agent name, unique within an organization.
	Name string `json:"name"`
	// OrgID is the organization that owns this agent.
	OrgID string `json:"org_id"`
	// Framework is the AI framework used (e.g., "openai", "langchain", "custom").
	Framework string `json:"framework"`
	// PublicKey is the agent's Ed25519 public key (PEM-encoded).
	PublicKey string `json:"public_key"`
	// Status is the agent's current status ("active", "suspended", "revoked").
	Status string `json:"status"`
	// Capabilities lists the permissions the agent can request (e.g., "files:read").
	Capabilities []string `json:"capabilities"`
	// Metadata holds arbitrary key-value pairs associated with the agent.
	Metadata map[string]interface{} `json:"metadata"`
	// CreatedAt is when the agent was registered.
	CreatedAt *time.Time `json:"created_at,omitempty"`
	// PrivateKey is the agent's private key. Only populated during agent creation.
	// Store this securely; it cannot be retrieved again.
	PrivateKey string `json:"private_key,omitempty"`
}

// CreateAgentRequest contains the parameters for creating a new agent.
type CreateAgentRequest struct {
	// Name is the agent name (required).
	Name string `json:"name"`
	// Framework is the AI framework (default: "custom").
	Framework string `json:"framework,omitempty"`
	// Capabilities lists the permissions the agent can request.
	Capabilities []string `json:"capabilities,omitempty"`
	// Metadata holds arbitrary key-value pairs.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	// OrgID is the organization ID (optional, uses default org if empty).
	OrgID string `json:"org_id,omitempty"`
}

// Token represents an opaque agent token issued by ATI.
//
// Tokens are random strings prefixed with "at_" (e.g. "at_xK3z9..."). They
// are NOT JWTs — they have no signature and cannot be validated client-side.
// To check a token, call (*TokensAPI).Introspect, which sends it to
// POST /api/v1/agent-tokens/introspect.
type Token struct {
	// Token is the opaque token string (e.g. "at_xK3z9...") for use in
	// Authorization: Bearer headers.
	Token string `json:"token"`
	// AgentID identifies the agent this token was issued to.
	AgentID string `json:"agent_id"`
	// Scopes lists the permissions granted by this token.
	Scopes []string `json:"scopes"`
	// Audience lists the intended recipients/resources for this token.
	Audience []string `json:"audience"`
	// IssuedAt is when the token was issued.
	IssuedAt *time.Time `json:"issued_at,omitempty"`
	// ExpiresAt is when the token expires.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// TokenID is the unique token identifier.
	TokenID string `json:"token_id,omitempty"`
}

// IssueTokenRequest contains the parameters for issuing a new capability token.
type IssueTokenRequest struct {
	// AgentID is the agent requesting the token (required).
	AgentID string `json:"agent_id"`
	// Scope lists the permissions to include in the token (required).
	Scope []string `json:"scopes"`
	// Audience is retained for source compatibility; opaque-token issuance no
	// longer sends target audience to the backend.
	//
	// Deprecated: use scopes plus server-side introspection.
	Audience []string `json:"-"`
	// TTL is the token time-to-live in seconds (default: 300).
	TTL int `json:"ttl,omitempty"`
	// SessionID optionally binds the issued token to an AgentTrust session.
	SessionID string `json:"session_id,omitempty"`
}

// IntrospectTokenRequest contains parameters for POST /api/v1/agent-tokens/introspect.
type IntrospectTokenRequest struct {
	// Token is the opaque agent token string to introspect (required).
	Token string `json:"token"`
	// Target is the resource being accessed (optional).
	Target string `json:"target,omitempty"`
	// RequiredScopes lists scopes that must be present in the token.
	RequiredScopes []string `json:"required_scopes,omitempty"`
}

// VerifyTokenRequest is a deprecated alias for IntrospectTokenRequest.
//
// Deprecated: Use IntrospectTokenRequest. The platform's verify endpoint was
// renamed to introspect when JWTs were replaced with opaque tokens.
type VerifyTokenRequest = IntrospectTokenRequest

// IntrospectionResult contains the outcome of an opaque-token introspection.
type IntrospectionResult struct {
	// Active indicates whether the token is currently usable.
	Active bool `json:"active"`
	// AgentID is the agent that owns the token.
	AgentID string `json:"agent_id,omitempty"`
	// OrgID is the organization that owns the agent.
	OrgID string `json:"org_id,omitempty"`
	// Scopes lists the permissions granted by the token.
	Scopes []string `json:"scopes"`
	// ExpiresAt is when the token expires.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// Reasoning provides a human-readable explanation of the decision.
	Reasoning string `json:"reasoning,omitempty"`
	// GuardTier is the security check tier used ("fast", "spot", "deep").
	GuardTier string `json:"guard_tier,omitempty"`
	// Confidence is the confidence score of the authorization decision (0.0-1.0).
	Confidence *float64 `json:"confidence,omitempty"`
	// LatencyMs is the time taken for the check in milliseconds.
	LatencyMs *int `json:"latency_ms,omitempty"`
}

// VerificationResult is a deprecated alias for IntrospectionResult.
//
// Deprecated: Use IntrospectionResult.
type VerificationResult = IntrospectionResult

// ActionCheckRequest contains the parameters for a pre-flight action check.
type ActionCheckRequest struct {
	// AgentID is the agent requesting the action (required).
	AgentID string `json:"agent_id"`
	// Action is the type of action being performed (default: "tool_call").
	Action string `json:"action,omitempty"`
	// ToolName is the name of the tool being invoked (required).
	ToolName string `json:"tool_name"`
	// ToolInputSummary is a truncated summary of the tool input (max 200 chars).
	ToolInputSummary string `json:"tool_input_summary,omitempty"`
	// SessionID is the current session ID for event correlation.
	SessionID string `json:"session_id,omitempty"`
	// ActionEffect is a hint for the effect classification (read, mutating, destructive, admin).
	// If empty, the backend auto-classifies the action.
	ActionEffect string `json:"action_effect,omitempty"`
}

// ActionCheckResult contains the outcome of a pre-flight action check.
type ActionCheckResult struct {
	// Allowed indicates whether the action is authorized.
	Allowed bool `json:"allowed"`
	// CheckID is the unique identifier for this check.
	CheckID string `json:"check_id,omitempty"`
	// Confidence is the confidence score (0.0-1.0).
	Confidence *float64 `json:"confidence,omitempty"`
	// GuardTier is the security check tier used ("fast", "spot", "deep").
	GuardTier string `json:"guard_tier,omitempty"`
	// LatencyMs is the time taken for the check in milliseconds.
	LatencyMs *int `json:"latency_ms,omitempty"`
	// Reason provides a human-readable explanation of the decision.
	Reason string `json:"reason,omitempty"`
	// ElevationRequired indicates the action needs approval before proceeding.
	ElevationRequired bool `json:"elevation_required,omitempty"`
	// ApprovalID is the ID of the pending approval request when elevation is required.
	ApprovalID string `json:"approval_id,omitempty"`
}

// Session represents an AgentTrust session for protocol-agnostic authorization.
type Session struct {
	SessionID      string   `json:"session_id"`
	AgentID        string   `json:"agent_id"`
	OrgID          string   `json:"org_id"`
	Source         string   `json:"source"`
	ServerID       string   `json:"server_id,omitempty"`
	DelegationID   string   `json:"delegation_id,omitempty"`
	ProviderID     string   `json:"provider_id,omitempty"`
	Issuer         string   `json:"issuer,omitempty"`
	TrustLevel     string   `json:"trust_level,omitempty"`
	Mode           string   `json:"mode"`
	AllowedActions []string `json:"allowed_actions"`
	ScopeCeiling   []string `json:"scope_ceiling"`
	TotalCalls     int      `json:"total_calls"`
	ReadCalls      int      `json:"read_calls"`
	WriteCalls     int      `json:"write_calls"`
	DeniedCalls    int      `json:"denied_calls"`
	CreatedAt      string   `json:"created_at,omitempty"`
	LastActivityAt string   `json:"last_activity_at,omitempty"`
}

// InitSessionRequest contains the parameters for initializing an AgentTrust session.
type InitSessionRequest struct {
	AgentID  string `json:"agent_id"`
	ServerID string `json:"server_id"`
}

// InitAPISessionRequest contains the parameters for creating an AgentTrust
// session from an already-issued AgentTrust ID API token.
type InitAPISessionRequest struct {
	Token string `json:"token"`
}

// Delegation represents a capability delegation from one agent to another.
type Delegation struct {
	ID              string                 `json:"id"`
	FromAgentID     string                 `json:"from_agent_id"`
	ToAgentID       string                 `json:"to_agent_id"`
	OrgID           string                 `json:"org_id,omitempty"`
	Scope           []string               `json:"scope"`
	Restrictions    map[string]interface{} `json:"restrictions,omitempty"`
	DelegationChain []string               `json:"delegation_chain,omitempty"`
	ExpiresAt       string                 `json:"expires_at,omitempty"`
	RevokedAt       string                 `json:"revoked_at,omitempty"`
	CreatedAt       string                 `json:"created_at,omitempty"`
}

// CreateDelegationRequest contains the parameters for creating a delegation.
type CreateDelegationRequest struct {
	FromAgentID        string                 `json:"from_agent_id"`
	ToAgentID          string                 `json:"to_agent_id"`
	Scope              []string               `json:"scope"`
	TTLSeconds         int                    `json:"ttl_seconds,omitempty"`
	Restrictions       map[string]interface{} `json:"restrictions,omitempty"`
	ParentDelegationID string                 `json:"parent_delegation_id,omitempty"`
}

// ApprovalRequestStatus represents a pending or resolved elevation approval.
type ApprovalRequestStatus struct {
	ID           string `json:"id"`
	SessionID    string `json:"session_id"`
	AgentID      string `json:"agent_id"`
	OrgID        string `json:"org_id"`
	ActionName   string `json:"action_name"`
	ActionEffect string `json:"action_effect"`
	Status       string `json:"status"`
	CreatedAt    string `json:"created_at,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	DecidedBy    string `json:"decided_by,omitempty"`
}

// TelemetryEvent represents a single telemetry event for agent behavior tracking.
type TelemetryEvent struct {
	// EventType is the type of event (e.g., "tool_start", "tool_end", "tool_error").
	EventType string `json:"event_type"`
	// ToolName is the name of the tool involved.
	ToolName string `json:"tool_name"`
	// DurationMs is how long the operation took in milliseconds.
	DurationMs int `json:"duration_ms,omitempty"`
	// Success indicates whether the operation succeeded.
	Success bool `json:"success,omitempty"`
	// ErrorType is the error class name if the operation failed.
	ErrorType string `json:"error_type,omitempty"`
	// Timestamp is the ISO 8601 timestamp of the event.
	Timestamp string `json:"timestamp,omitempty"`
}

// TelemetryReportRequest contains the parameters for reporting telemetry events.
type TelemetryReportRequest struct {
	// AgentID identifies the agent that generated the events.
	AgentID string `json:"agent_id"`
	// SessionID is the session ID for event correlation.
	SessionID string `json:"session_id"`
	// Events is the list of telemetry events to report.
	Events []TelemetryEvent `json:"events"`
}

// HealthResponse contains the result of a health check.
type HealthResponse struct {
	// Status is the service health status ("healthy", "degraded", "unhealthy").
	Status string `json:"status"`
	// Service is the name of the service responding.
	Service string `json:"service,omitempty"`
	// Version is the service version.
	Version string `json:"version,omitempty"`
}

// createAgentAPIRequest is the wire format sent to the API.
// This differs from CreateAgentRequest to ensure correct JSON field naming.
type createAgentAPIRequest struct {
	Name         string                 `json:"name"`
	Framework    string                 `json:"framework"`
	Capabilities []string               `json:"capabilities"`
	Metadata     map[string]interface{} `json:"metadata"`
	OrgID        string                 `json:"org_id,omitempty"`
}

// createAgentResponse is the wire format returned by the API when creating an agent.
// The API may wrap the response in {"agent": {...}}.
type createAgentResponse struct {
	// Flat fields (when API returns agent data directly)
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	OrgID        string                 `json:"org_id"`
	Framework    string                 `json:"framework"`
	PublicKey    string                 `json:"public_key"`
	Status       string                 `json:"status"`
	Capabilities []string               `json:"capabilities"`
	Metadata     map[string]interface{} `json:"metadata"`
	CreatedAt    string                 `json:"created_at"`
	PrivateKey   string                 `json:"private_key"`

	// Nested response format
	Agent *agentData `json:"agent,omitempty"`
}

// agentData is the nested agent object within API responses.
type agentData struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	OrgID        string                 `json:"org_id"`
	Framework    string                 `json:"framework"`
	PublicKey    string                 `json:"public_key"`
	Status       string                 `json:"status"`
	Capabilities []string               `json:"capabilities"`
	Metadata     map[string]interface{} `json:"metadata"`
	CreatedAt    string                 `json:"created_at"`
	PrivateKey   string                 `json:"private_key"`
}

// agentListResponse is the wire format for the list agents endpoint.
type agentListResponse struct {
	Agents []agentData `json:"agents"`
}

// issueTokenResponse is the wire format returned by the token issue endpoint.
type issueTokenResponse struct {
	Token      string   `json:"token"`
	AgentToken string   `json:"agent_token"`
	AgentID    string   `json:"agent_id"`
	Scopes     []string `json:"scopes"`
	Scope      []string `json:"scope"`
	Audience   []string `json:"audience"`
	IssuedAt   string   `json:"issued_at"`
	ExpiresAt  string   `json:"expires_at"`
	TokenID    string   `json:"token_id"`
	ID         string   `json:"id"`
}

// telemetryReportResponse is the wire format returned by the telemetry report endpoint.
type telemetryReportResponse struct {
	Accepted        bool `json:"accepted"`
	EventsProcessed int  `json:"events_processed"`
}

// revokeRequest is the wire format for revocation endpoints.
type revokeRequest struct {
	Reason string `json:"reason"`
}

// revokeTokenRequest is the wire format for the token revocation endpoint.
type revokeTokenRequest struct {
	Token  string `json:"token"`
	Reason string `json:"reason"`
}

// parseTime parses an ISO 8601 / RFC 3339 timestamp string.
// Returns nil if the string is empty or cannot be parsed.
func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	// Try RFC 3339 first (most common API format)
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		// Try RFC 3339 with nanoseconds
		t, err = time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return nil
		}
	}
	return &t
}

// parseAgentFromData converts an agentData wire format to an Agent.
func parseAgentFromData(ad *agentData) *Agent {
	if ad == nil {
		return nil
	}
	status := ad.Status
	if status == "" {
		status = "active"
	}
	framework := ad.Framework
	if framework == "" {
		framework = "custom"
	}
	caps := ad.Capabilities
	if caps == nil {
		caps = []string{}
	}
	meta := ad.Metadata
	if meta == nil {
		meta = map[string]interface{}{}
	}
	return &Agent{
		ID:           ad.ID,
		Name:         ad.Name,
		OrgID:        ad.OrgID,
		Framework:    framework,
		PublicKey:    ad.PublicKey,
		Status:       status,
		Capabilities: caps,
		Metadata:     meta,
		CreatedAt:    parseTime(ad.CreatedAt),
		PrivateKey:   ad.PrivateKey,
	}
}

// parseTokenFromResponse converts an issueTokenResponse to a Token.
func parseTokenFromResponse(r *issueTokenResponse) *Token {
	tok := r.Token
	if tok == "" {
		tok = r.AgentToken
	}
	scopes := r.Scopes
	if len(scopes) == 0 {
		scopes = r.Scope
	}
	if scopes == nil {
		scopes = []string{}
	}
	audience := r.Audience
	if audience == nil {
		audience = []string{}
	}
	tokenID := r.TokenID
	if tokenID == "" {
		tokenID = r.ID
	}
	return &Token{
		Token:     tok,
		AgentID:   r.AgentID,
		Scopes:    scopes,
		Audience:  audience,
		IssuedAt:  parseTime(r.IssuedAt),
		ExpiresAt: parseTime(r.ExpiresAt),
		TokenID:   tokenID,
	}
}
