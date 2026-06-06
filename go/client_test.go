package agenttrust

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// newTestServer creates an httptest.Server with a handler that routes
// requests based on method and path. The routes map keys are "METHOD /path".
func newTestServer(routes map[string]http.HandlerFunc) *httptest.Server {
	mux := http.NewServeMux()
	for pattern, handler := range routes {
		parts := strings.SplitN(pattern, " ", 2)
		method := parts[0]
		path := parts[1]
		m := method
		h := handler
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != m {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			h(w, r)
		})
	}
	return httptest.NewServer(mux)
}

// jsonHandler returns an http.HandlerFunc that writes a JSON response.
func jsonHandler(status int, v interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(v)
	}
}

// --- TestNewClient ---

func TestNewClient_Defaults(t *testing.T) {
	c := NewClient()
	if c.baseURL != DefaultBaseURL {
		t.Errorf("expected baseURL=%q, got %q", DefaultBaseURL, c.baseURL)
	}
	if c.Agents == nil {
		t.Error("expected Agents to be initialized")
	}
	if c.Tokens == nil {
		t.Error("expected Tokens to be initialized")
	}
	if c.Actions == nil {
		t.Error("expected Actions to be initialized")
	}
	if c.Telemetry == nil {
		t.Error("expected Telemetry to be initialized")
	}
	if c.Federation == nil {
		t.Error("expected Federation to be initialized")
	}
	if c.WIMSE == nil {
		t.Error("expected WIMSE to be initialized")
	}
	if c.Guardian == nil {
		t.Error("expected Guardian to be initialized")
	}
	if c.Streaming == nil {
		t.Error("expected Streaming to be initialized")
	}
	if c.Delegations == nil {
		t.Error("expected Delegations to be initialized")
	}
	if c.Sessions == nil {
		t.Error("expected Sessions to be initialized")
	}
	if c.Approvals == nil {
		t.Error("expected Approvals to be initialized")
	}
}

func TestNewClient_WithOptions(t *testing.T) {
	c := NewClient(
		WithBaseURL("http://custom:9090"),
		WithAPIKey("sk_test_123"),
		WithTimeout(5*time.Second),
	)
	if c.baseURL != "http://custom:9090" {
		t.Errorf("expected baseURL=%q, got %q", "http://custom:9090", c.baseURL)
	}
	if c.apiKey != "sk_test_123" {
		t.Errorf("expected apiKey=%q, got %q", "sk_test_123", c.apiKey)
	}
	if c.httpClient.Timeout != 5*time.Second {
		t.Errorf("expected timeout=%v, got %v", 5*time.Second, c.httpClient.Timeout)
	}
}

func TestNewClient_WithHTTPClient(t *testing.T) {
	custom := &http.Client{Timeout: 99 * time.Second}
	c := NewClient(WithHTTPClient(custom))
	if c.httpClient != custom {
		t.Error("expected custom HTTP client to be used")
	}
}

func TestNewClient_TrailingSlashTrimmed(t *testing.T) {
	c := NewClient(WithBaseURL("http://example.com/"))
	if c.baseURL != "http://example.com" {
		t.Errorf("expected trailing slash trimmed, got %q", c.baseURL)
	}
}

func TestFromEnv(t *testing.T) {
	os.Setenv("AGENTTRUST_URL", "http://env-url:8080")
	os.Setenv("AGENTTRUST_API_KEY", "sk_env_key")
	defer os.Unsetenv("AGENTTRUST_URL")
	defer os.Unsetenv("AGENTTRUST_API_KEY")

	c := FromEnv()
	if c.baseURL != "http://env-url:8080" {
		t.Errorf("expected baseURL from env, got %q", c.baseURL)
	}
	if c.apiKey != "sk_env_key" {
		t.Errorf("expected apiKey from env, got %q", c.apiKey)
	}
}

func TestFromEnv_FallbackBaseURL(t *testing.T) {
	os.Setenv("AGENTTRUST_BASE_URL", "http://fallback:8080")
	defer os.Unsetenv("AGENTTRUST_BASE_URL")

	c := FromEnv()
	if c.baseURL != "http://fallback:8080" {
		t.Errorf("expected baseURL from AGENTTRUST_BASE_URL, got %q", c.baseURL)
	}
}

func TestFromEnv_Defaults(t *testing.T) {
	// Ensure env vars are unset
	os.Unsetenv("AGENTTRUST_URL")
	os.Unsetenv("AGENTTRUST_BASE_URL")
	os.Unsetenv("AGENTTRUST_API_KEY")

	c := FromEnv()
	if c.baseURL != DefaultBaseURL {
		t.Errorf("expected default baseURL, got %q", c.baseURL)
	}
	if c.apiKey != "" {
		t.Errorf("expected empty apiKey, got %q", c.apiKey)
	}
}

// --- TestHealth ---

func TestHealth(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"GET /health": jsonHandler(200, map[string]string{
			"status":  "healthy",
			"service": "gateway",
			"version": "1.0.0",
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	health, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if health.Status != "healthy" {
		t.Errorf("expected status=healthy, got %q", health.Status)
	}
	if health.Service != "gateway" {
		t.Errorf("expected service=gateway, got %q", health.Service)
	}
	if health.Version != "1.0.0" {
		t.Errorf("expected version=1.0.0, got %q", health.Version)
	}
}

// --- TestAgentsCreate ---

func TestAgentsCreate(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agents": func(w http.ResponseWriter, r *http.Request) {
			// Verify API key header
			if r.Header.Get("X-API-Key") != "sk_test" {
				http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			var body createAgentAPIRequest
			json.NewDecoder(r.Body).Decode(&body)
			if body.Name == "" {
				http.Error(w, `{"message":"name is required"}`, http.StatusBadRequest)
				return
			}

			resp := map[string]interface{}{
				"agent": map[string]interface{}{
					"id":           "agent-123",
					"name":         body.Name,
					"org_id":       "org-1",
					"framework":    body.Framework,
					"public_key":   "-----BEGIN PUBLIC KEY-----",
					"status":       "active",
					"capabilities": body.Capabilities,
					"metadata":     body.Metadata,
					"created_at":   "2026-01-01T00:00:00Z",
					"private_key":  "-----BEGIN PRIVATE KEY-----",
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL), WithAPIKey("sk_test"))
	agent, err := c.Agents.Create(context.Background(), CreateAgentRequest{
		Name:         "test-agent",
		Framework:    "langchain",
		Capabilities: []string{"web_search", "files:read"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if agent.ID != "agent-123" {
		t.Errorf("expected ID=agent-123, got %q", agent.ID)
	}
	if agent.Name != "test-agent" {
		t.Errorf("expected Name=test-agent, got %q", agent.Name)
	}
	if agent.Framework != "langchain" {
		t.Errorf("expected Framework=langchain, got %q", agent.Framework)
	}
	if agent.Status != "active" {
		t.Errorf("expected Status=active, got %q", agent.Status)
	}
	if len(agent.Capabilities) != 2 {
		t.Errorf("expected 2 capabilities, got %d", len(agent.Capabilities))
	}
	if agent.PrivateKey != "-----BEGIN PRIVATE KEY-----" {
		t.Errorf("expected PrivateKey to be set, got %q", agent.PrivateKey)
	}
}

func TestAgentsCreate_Error(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agents": jsonHandler(400, map[string]string{
			"message": "name is required",
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	_, err := c.Agents.Create(context.Background(), CreateAgentRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	var valErr *ValidationError
	if !errors.As(err, &valErr) {
		t.Errorf("expected ValidationError, got %T: %v", err, err)
	}
}

// --- TestAgentsGet ---

func TestAgentsGet(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"GET /api/v1/agents/agent-123": jsonHandler(200, map[string]interface{}{
			"id":           "agent-123",
			"name":         "my-agent",
			"org_id":       "org-1",
			"framework":    "custom",
			"status":       "active",
			"capabilities": []string{"read"},
			"created_at":   "2026-01-01T00:00:00Z",
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	agent, err := c.Agents.Get(context.Background(), "agent-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if agent.ID != "agent-123" {
		t.Errorf("expected ID=agent-123, got %q", agent.ID)
	}
	if agent.Name != "my-agent" {
		t.Errorf("expected Name=my-agent, got %q", agent.Name)
	}
}

func TestAgentsGet_NotFound(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"GET /api/v1/agents/nonexistent": jsonHandler(404, map[string]string{
			"message": "agent not found",
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	_, err := c.Agents.Get(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
	var notFoundErr *NotFoundError
	if !errors.As(err, &notFoundErr) {
		t.Errorf("expected NotFoundError, got %T: %v", err, err)
	}
}

// --- TestAgentsList ---

func TestAgentsList(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"GET /api/v1/agents": jsonHandler(200, map[string]interface{}{
			"agents": []map[string]interface{}{
				{"id": "a1", "name": "agent-1", "status": "active", "framework": "custom", "capabilities": []string{}},
				{"id": "a2", "name": "agent-2", "status": "revoked", "framework": "langchain", "capabilities": []string{"search"}},
			},
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	agents, err := c.Agents.List(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(agents) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(agents))
	}
	if agents[0].Name != "agent-1" {
		t.Errorf("expected first agent name=agent-1, got %q", agents[0].Name)
	}
	if agents[1].Status != "revoked" {
		t.Errorf("expected second agent status=revoked, got %q", agents[1].Status)
	}
}

// --- TestAgentsRevoke ---

func TestAgentsRevoke(t *testing.T) {
	var receivedReason string
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agents/agent-123/revoke": func(w http.ResponseWriter, r *http.Request) {
			var body revokeRequest
			json.NewDecoder(r.Body).Decode(&body)
			receivedReason = body.Reason
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]bool{"success": true})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	err := c.Agents.Revoke(context.Background(), "agent-123", "compromised")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedReason != "compromised" {
		t.Errorf("expected reason=compromised, got %q", receivedReason)
	}
}

// --- TestTokensIssue ---

func TestTokensIssue(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agent-tokens/issue": jsonHandler(200, map[string]interface{}{
			"token":      "at_xK3z9abcdef123",
			"agent_id":   "agent-123",
			"scopes":     []string{"files:read"},
			"audience":   []string{"mcp://filesystem"},
			"issued_at":  "2026-01-01T00:00:00Z",
			"expires_at": "2026-01-01T00:05:00Z",
			"token_id":   "tok-456",
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	token, err := c.Tokens.Issue(context.Background(), IssueTokenRequest{
		AgentID:  "agent-123",
		Scope:    []string{"files:read"},
		Audience: []string{"mcp://filesystem"},
		TTL:      300,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(token.Token, "at_") {
		t.Errorf("expected opaque token to start with 'at_', got %q", token.Token)
	}
	if token.AgentID != "agent-123" {
		t.Errorf("expected AgentID=agent-123, got %q", token.AgentID)
	}
	if len(token.Scopes) != 1 || token.Scopes[0] != "files:read" {
		t.Errorf("expected Scopes=[files:read], got %v", token.Scopes)
	}
	if token.TokenID != "tok-456" {
		t.Errorf("expected TokenID=tok-456, got %q", token.TokenID)
	}
}

// --- TestTokensIntrospect ---

func TestTokensIntrospect(t *testing.T) {
	confidence := 0.95
	latencyMs := 12
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agent-tokens/introspect": jsonHandler(200, map[string]interface{}{
			"active":     true,
			"agent_id":   "agent-123",
			"org_id":     "org-1",
			"scopes":     []string{"files:read"},
			"reasoning":  "capability match",
			"guard_tier": "fast",
			"confidence": confidence,
			"latency_ms": latencyMs,
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	result, err := c.Tokens.Introspect(context.Background(), IntrospectTokenRequest{
		Token:          "at_test",
		Target:         "mcp://filesystem",
		RequiredScopes: []string{"files:read"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Active {
		t.Error("expected Active=true")
	}
	if result.AgentID != "agent-123" {
		t.Errorf("expected AgentID=agent-123, got %q", result.AgentID)
	}
	if result.OrgID != "org-1" {
		t.Errorf("expected OrgID=org-1, got %q", result.OrgID)
	}
	if result.GuardTier != "fast" {
		t.Errorf("expected GuardTier=fast, got %q", result.GuardTier)
	}
}

// --- TestTokensRevoke ---

func TestTokensRevoke(t *testing.T) {
	var receivedToken, receivedReason string
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agent-tokens/revoke": func(w http.ResponseWriter, r *http.Request) {
			var body revokeTokenRequest
			json.NewDecoder(r.Body).Decode(&body)
			receivedToken = body.Token
			receivedReason = body.Reason
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]bool{"success": true})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	err := c.Tokens.Revoke(context.Background(), "at_revoke_me", "key_compromised")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedToken != "at_revoke_me" {
		t.Errorf("expected token=at_revoke_me, got %q", receivedToken)
	}
	if receivedReason != "key_compromised" {
		t.Errorf("expected reason=key_compromised, got %q", receivedReason)
	}
}

// --- TestActionsCheck ---

func TestActionsCheck_Allowed(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agenttrust/check": jsonHandler(200, map[string]interface{}{
			"allowed":    true,
			"check_id":   "chk-1",
			"confidence": 0.95,
			"guard_tier": "fast",
			"latency_ms": 12,
			"reason":     "capability match",
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	result, err := c.Actions.Check(context.Background(), ActionCheckRequest{
		AgentID:          "agent-1",
		ToolName:         "web_search",
		ToolInputSummary: "search query",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Error("expected Allowed=true")
	}
	if result.CheckID != "chk-1" {
		t.Errorf("expected CheckID=chk-1, got %q", result.CheckID)
	}
	if result.GuardTier != "fast" {
		t.Errorf("expected GuardTier=fast, got %q", result.GuardTier)
	}
}

func TestActionsCheck_Denied(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agenttrust/check": jsonHandler(200, map[string]interface{}{
			"allowed":    false,
			"confidence": 0.95,
			"guard_tier": "fast",
			"reason":     "capability not registered",
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	result, err := c.Actions.Check(context.Background(), ActionCheckRequest{
		AgentID:  "agent-1",
		ToolName: "delete_all",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("expected Allowed=false")
	}
	if result.Reason != "capability not registered" {
		t.Errorf("expected Reason='capability not registered', got %q", result.Reason)
	}
}

func TestActionsCheck_TruncatesInput(t *testing.T) {
	var receivedSummary string
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agenttrust/check": func(w http.ResponseWriter, r *http.Request) {
			var body ActionCheckRequest
			json.NewDecoder(r.Body).Decode(&body)
			receivedSummary = body.ToolInputSummary
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"allowed": true})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	longInput := strings.Repeat("x", 500)
	_, err := c.Actions.Check(context.Background(), ActionCheckRequest{
		AgentID:          "agent-1",
		ToolName:         "tool_a",
		ToolInputSummary: longInput,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(receivedSummary) > 200 {
		t.Errorf("expected input truncated to 200 chars, got %d", len(receivedSummary))
	}
}

// --- TestTelemetryReport ---

func TestTelemetryReport(t *testing.T) {
	var receivedReport TelemetryReportRequest
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/telemetry/report": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&receivedReport)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"accepted":         true,
				"events_processed": len(receivedReport.Events),
			})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	err := c.Telemetry.Report(context.Background(), "agent-1", "sess-1", []TelemetryEvent{
		{EventType: "tool_end", ToolName: "search", DurationMs: 100, Success: true, Timestamp: "2026-01-01T00:00:00Z"},
		{EventType: "tool_error", ToolName: "analyze", DurationMs: 50, Success: false, ErrorType: "timeout", Timestamp: "2026-01-01T00:00:01Z"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedReport.AgentID != "agent-1" {
		t.Errorf("expected agent_id=agent-1, got %q", receivedReport.AgentID)
	}
	if len(receivedReport.Events) != 2 {
		t.Errorf("expected 2 events, got %d", len(receivedReport.Events))
	}
}

// --- TestGuardCheck ---

func TestGuardCheck_Allowed(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agenttrust/check": jsonHandler(200, map[string]interface{}{
			"allowed":    true,
			"check_id":   "chk-1",
			"confidence": 0.95,
			"guard_tier": "fast",
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	guard := NewGuard(c, "agent-1")

	err := guard.Check(context.Background(), "web_search", "query about AI")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestGuardCheck_Denied_BlockOnDeny(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agenttrust/check": jsonHandler(200, map[string]interface{}{
			"allowed": false,
			"reason":  "capability not registered",
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	guard := NewGuard(c, "agent-1") // blockOnDeny=true by default

	err := guard.Check(context.Background(), "drop_database", "")
	if err == nil {
		t.Fatal("expected error for denied action")
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Errorf("expected error to contain 'denied', got: %v", err)
	}
}

func TestGuardCheck_Denied_NoBlock(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agenttrust/check": jsonHandler(200, map[string]interface{}{
			"allowed": false,
			"reason":  "not registered",
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	guard := NewGuard(c, "agent-1", WithBlockOnDeny(false))

	err := guard.Check(context.Background(), "dangerous_tool", "")
	if err != nil {
		t.Fatalf("expected no error with blockOnDeny=false, got: %v", err)
	}
}

func TestGuardCheck_NetworkError_FailClosed(t *testing.T) {
	// Point at a server that doesn't exist
	c := NewClient(WithBaseURL("http://127.0.0.1:1"), WithTimeout(100*time.Millisecond))
	guard := NewGuard(c, "agent-1") // failOpen=false by default

	err := guard.Check(context.Background(), "web_search", "")
	if err == nil {
		t.Fatal("expected error when Guardian is unreachable")
	}
	if !strings.Contains(err.Error(), "Guardian unreachable") {
		t.Errorf("expected 'Guardian unreachable' error, got: %v", err)
	}
}

func TestGuardCheck_NetworkError_FailOpen(t *testing.T) {
	// Point at a server that doesn't exist
	c := NewClient(WithBaseURL("http://127.0.0.1:1"), WithTimeout(100*time.Millisecond))
	guard := NewGuard(c, "agent-1", WithFailOpen(true))

	err := guard.Check(context.Background(), "web_search", "")
	if err != nil {
		t.Fatalf("expected nil with failOpen=true, got: %v", err)
	}
}

func TestGuardCheck_CustomSessionID(t *testing.T) {
	var receivedSessionID string
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agenttrust/check": func(w http.ResponseWriter, r *http.Request) {
			var body ActionCheckRequest
			json.NewDecoder(r.Body).Decode(&body)
			receivedSessionID = body.SessionID
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"allowed": true})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	guard := NewGuard(c, "agent-1", WithSessionID("my-session-id"))

	err := guard.Check(context.Background(), "tool_a", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedSessionID != "my-session-id" {
		t.Errorf("expected session_id=my-session-id, got %q", receivedSessionID)
	}
}

// --- TestGuardReport ---

func TestGuardReport_BuffersEvents(t *testing.T) {
	callCount := 0
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/telemetry/report": func(w http.ResponseWriter, r *http.Request) {
			callCount++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"accepted": true})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	guard := NewGuard(c, "agent-1")

	// Report fewer than 10 events -- should not trigger a flush
	guard.Report("search", true, 120)
	guard.Report("analyze", false, 50)

	if callCount != 0 {
		t.Errorf("expected no flush yet, got %d calls", callCount)
	}
}

func TestGuardReport_AutoFlushAt10(t *testing.T) {
	var receivedEvents []TelemetryEvent
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/telemetry/report": func(w http.ResponseWriter, r *http.Request) {
			var body TelemetryReportRequest
			json.NewDecoder(r.Body).Decode(&body)
			receivedEvents = append(receivedEvents, body.Events...)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"accepted": true})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	guard := NewGuard(c, "agent-1")

	for i := 0; i < 10; i++ {
		guard.Report("tool_"+string(rune('a'+i)), true, 10)
	}

	// Auto-flush should have been triggered
	if len(receivedEvents) != 10 {
		t.Errorf("expected 10 events after auto-flush, got %d", len(receivedEvents))
	}
}

func TestGuardFlush(t *testing.T) {
	var receivedEvents []TelemetryEvent
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/telemetry/report": func(w http.ResponseWriter, r *http.Request) {
			var body TelemetryReportRequest
			json.NewDecoder(r.Body).Decode(&body)
			receivedEvents = body.Events
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"accepted": true})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	guard := NewGuard(c, "agent-1")

	guard.Report("search", true, 120)
	guard.Report("analyze", true, 200)

	err := guard.Flush(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(receivedEvents) != 2 {
		t.Errorf("expected 2 flushed events, got %d", len(receivedEvents))
	}
	if receivedEvents[0].ToolName != "search" {
		t.Errorf("expected first event tool=search, got %q", receivedEvents[0].ToolName)
	}
}

func TestGuardFlush_Empty(t *testing.T) {
	c := NewClient(WithBaseURL("http://unused"))
	guard := NewGuard(c, "agent-1")

	err := guard.Flush(context.Background())
	if err != nil {
		t.Fatalf("expected no error flushing empty buffer, got: %v", err)
	}
}

func TestGuardClose(t *testing.T) {
	flushCalled := false
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/telemetry/report": func(w http.ResponseWriter, r *http.Request) {
			flushCalled = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"accepted": true})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	guard := NewGuard(c, "agent-1")
	guard.Report("tool_a", true, 10)

	err := guard.Close(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !flushCalled {
		t.Error("expected Close to flush remaining events")
	}
}

// --- TestErrorHandling ---

func TestError_Authentication(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"GET /health": jsonHandler(401, map[string]string{"message": "invalid key"}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	_, err := c.Health(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var authErr *AuthenticationError
	if !errors.As(err, &authErr) {
		t.Errorf("expected AuthenticationError, got %T: %v", err, err)
	}
}

func TestError_Authorization(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"GET /health": jsonHandler(403, map[string]string{"message": "forbidden"}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	_, err := c.Health(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var authzErr *AuthorizationError
	if !errors.As(err, &authzErr) {
		t.Errorf("expected AuthorizationError, got %T: %v", err, err)
	}
}

func TestError_ServerError(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"GET /health": jsonHandler(500, map[string]string{"message": "internal error"}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	_, err := c.Health(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var atiErr *AgentTrustError
	if !errors.As(err, &atiErr) {
		t.Errorf("expected AgentTrustError, got %T: %v", err, err)
	}
}

func TestError_NetworkError(t *testing.T) {
	c := NewClient(WithBaseURL("http://127.0.0.1:1"), WithTimeout(100*time.Millisecond))
	_, err := c.Health(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Errorf("expected NetworkError, got %T: %v", err, err)
	}
}

func TestError_APIKeyHeader(t *testing.T) {
	var receivedKey string
	srv := newTestServer(map[string]http.HandlerFunc{
		"GET /health": func(w http.ResponseWriter, r *http.Request) {
			receivedKey = r.Header.Get("X-API-Key")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL), WithAPIKey("sk_test_abc"))
	_, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedKey != "sk_test_abc" {
		t.Errorf("expected X-API-Key=sk_test_abc, got %q", receivedKey)
	}
}

// --- TestParseTime ---

func TestParseTime(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"2026-01-01T00:00:00Z", true},
		{"2026-01-01T00:00:00.123456789Z", true},
		{"2026-01-01T00:00:00+00:00", true},
		{"", false},
		{"invalid", false},
	}
	for _, tt := range tests {
		result := parseTime(tt.input)
		if tt.valid && result == nil {
			t.Errorf("parseTime(%q): expected non-nil result", tt.input)
		}
		if !tt.valid && result != nil {
			t.Errorf("parseTime(%q): expected nil result, got %v", tt.input, result)
		}
	}
}

// --- TestGenerateUUID ---

func TestGenerateUUID(t *testing.T) {
	uuid := generateUUID()
	if len(uuid) != 36 {
		t.Errorf("expected UUID length=36, got %d: %q", len(uuid), uuid)
	}
	// Check format: 8-4-4-4-12
	parts := strings.Split(uuid, "-")
	if len(parts) != 5 {
		t.Errorf("expected 5 UUID parts, got %d", len(parts))
	}
}

// --- TestSessionsAPI ---

func TestSessionsInitSession(t *testing.T) {
	var receivedBody map[string]string
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /mcp/sessions/init": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&receivedBody)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"session_id":      "sess-001",
				"agent_id":        "agent-123",
				"org_id":          "org-456",
				"source":          "mcp",
				"server_id":       "srv-001",
				"mode":            "read_only",
				"allowed_actions": []string{"files:read"},
				"scope_ceiling":   []string{"files:read", "files:write"},
				"total_calls":     0,
				"read_calls":      0,
				"write_calls":     0,
				"denied_calls":    0,
				"created_at":      "2026-03-01T10:00:00Z",
			})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	session, err := c.Sessions.InitSession(context.Background(), InitSessionRequest{
		AgentID:  "agent-123",
		ServerID: "srv-001",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session.SessionID != "sess-001" {
		t.Errorf("expected SessionID=sess-001, got %q", session.SessionID)
	}
	if session.AgentID != "agent-123" {
		t.Errorf("expected AgentID=agent-123, got %q", session.AgentID)
	}
	if session.Mode != "read_only" {
		t.Errorf("expected Mode=read_only, got %q", session.Mode)
	}
	if session.ServerID != "srv-001" {
		t.Errorf("expected ServerID=srv-001, got %q", session.ServerID)
	}
	if len(session.AllowedActions) != 1 || session.AllowedActions[0] != "files:read" {
		t.Errorf("expected AllowedActions=[files:read], got %v", session.AllowedActions)
	}
	if len(session.ScopeCeiling) != 2 {
		t.Errorf("expected 2 ScopeCeiling entries, got %d", len(session.ScopeCeiling))
	}
	if receivedBody["agent_id"] != "agent-123" {
		t.Errorf("expected request agent_id=agent-123, got %q", receivedBody["agent_id"])
	}
	if receivedBody["server_id"] != "srv-001" {
		t.Errorf("expected request server_id=srv-001, got %q", receivedBody["server_id"])
	}
}

func TestSessionsGetSession(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"GET /mcp/sessions/sess-001": jsonHandler(200, map[string]interface{}{
			"session_id":   "sess-001",
			"agent_id":     "agent-123",
			"org_id":       "org-456",
			"mode":         "elevated",
			"total_calls":  5,
			"read_calls":   3,
			"write_calls":  2,
			"denied_calls": 0,
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	session, err := c.Sessions.GetSession(context.Background(), "sess-001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session.SessionID != "sess-001" {
		t.Errorf("expected SessionID=sess-001, got %q", session.SessionID)
	}
	if session.Mode != "elevated" {
		t.Errorf("expected Mode=elevated, got %q", session.Mode)
	}
	if session.TotalCalls != 5 {
		t.Errorf("expected TotalCalls=5, got %d", session.TotalCalls)
	}
	if session.ReadCalls != 3 {
		t.Errorf("expected ReadCalls=3, got %d", session.ReadCalls)
	}
	if session.WriteCalls != 2 {
		t.Errorf("expected WriteCalls=2, got %d", session.WriteCalls)
	}
}

func TestSessionsInitAPISession(t *testing.T) {
	var receivedBody map[string]string
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agenttrust/api-sessions/init": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&receivedBody)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"session_id":    "sess-api-001",
				"agent_id":      "agent-123",
				"source":        "api",
				"mode":          "read_only",
				"scope_ceiling": []string{"files:read"},
				"created_at":    "2026-03-01T10:00:00Z",
			})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	session, err := c.Sessions.InitAPISession(context.Background(), InitAPISessionRequest{
		Token: "eyJ.api-token",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session.SessionID != "sess-api-001" {
		t.Errorf("expected SessionID=sess-api-001, got %q", session.SessionID)
	}
	if session.Source != "api" {
		t.Errorf("expected Source=api, got %q", session.Source)
	}
	if receivedBody["token"] != "eyJ.api-token" {
		t.Errorf("expected request token to be sent, got %q", receivedBody["token"])
	}
}

// --- TestApprovalsAPI ---

func TestApprovalsApprove(t *testing.T) {
	var receivedBody map[string]string
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /mcp/approvals/apr-001/approve": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&receivedBody)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "approved"})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	err := c.Approvals.Approve(context.Background(), "apr-001", "admin@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedBody["decided_by"] != "admin@example.com" {
		t.Errorf("expected decided_by=admin@example.com, got %q", receivedBody["decided_by"])
	}
}

func TestApprovalsDeny(t *testing.T) {
	var receivedBody map[string]string
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /mcp/approvals/apr-001/deny": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&receivedBody)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "denied"})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	err := c.Approvals.Deny(context.Background(), "apr-001", "admin@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedBody["decided_by"] != "admin@example.com" {
		t.Errorf("expected decided_by=admin@example.com, got %q", receivedBody["decided_by"])
	}
}

func TestApprovalsGet(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"GET /mcp/approvals/apr-001": jsonHandler(200, map[string]interface{}{
			"id":            "apr-001",
			"session_id":    "sess-001",
			"agent_id":      "agent-123",
			"org_id":        "org-456",
			"action_name":   "delete_file",
			"action_effect": "destructive",
			"status":        "approved",
			"decided_by":    "admin@example.com",
			"created_at":    "2026-03-01T10:00:00Z",
			"expires_at":    "2026-03-01T10:15:00Z",
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	approval, err := c.Approvals.Get(context.Background(), "apr-001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if approval.ID != "apr-001" {
		t.Errorf("expected ID=apr-001, got %q", approval.ID)
	}
	if approval.SessionID != "sess-001" {
		t.Errorf("expected SessionID=sess-001, got %q", approval.SessionID)
	}
	if approval.ActionName != "delete_file" {
		t.Errorf("expected ActionName=delete_file, got %q", approval.ActionName)
	}
	if approval.ActionEffect != "destructive" {
		t.Errorf("expected ActionEffect=destructive, got %q", approval.ActionEffect)
	}
	if approval.Status != "approved" {
		t.Errorf("expected Status=approved, got %q", approval.Status)
	}
	if approval.DecidedBy != "admin@example.com" {
		t.Errorf("expected DecidedBy=admin@example.com, got %q", approval.DecidedBy)
	}
}

// --- TestActionsCheck with ActionEffect ---

func TestActionsCheck_WithActionEffect(t *testing.T) {
	var receivedBody ActionCheckRequest
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agenttrust/check": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&receivedBody)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"allowed": true})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	_, err := c.Actions.Check(context.Background(), ActionCheckRequest{
		AgentID:      "agent-1",
		ToolName:     "write_file",
		ActionEffect: "mutating",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedBody.ActionEffect != "mutating" {
		t.Errorf("expected ActionEffect=mutating, got %q", receivedBody.ActionEffect)
	}
}

func TestActionsCheck_ElevationRequired(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agenttrust/check": jsonHandler(200, map[string]interface{}{
			"allowed":            false,
			"reason":             "session is read_only",
			"elevation_required": true,
			"approval_id":        "apr-001",
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	result, err := c.Actions.Check(context.Background(), ActionCheckRequest{
		AgentID:  "agent-1",
		ToolName: "delete_file",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("expected Allowed=false")
	}
	if !result.ElevationRequired {
		t.Error("expected ElevationRequired=true")
	}
	if result.ApprovalID != "apr-001" {
		t.Errorf("expected ApprovalID=apr-001, got %q", result.ApprovalID)
	}
}

// --- TestGuard Elevation ---

func TestGuardCheck_ElevationRequired(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agenttrust/check": jsonHandler(200, map[string]interface{}{
			"allowed":            false,
			"reason":             "session is read_only",
			"elevation_required": true,
			"approval_id":        "apr-001",
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	guard := NewGuard(c, "agent-1")

	err := guard.Check(context.Background(), "delete_file", "")
	if err == nil {
		t.Fatal("expected error for elevation required")
	}
	var elevErr *ElevationRequiredError
	if !errors.As(err, &elevErr) {
		t.Fatalf("expected ElevationRequiredError, got %T: %v", err, err)
	}
	if elevErr.ApprovalID != "apr-001" {
		t.Errorf("expected ApprovalID=apr-001, got %q", elevErr.ApprovalID)
	}
	if elevErr.Code != "ELEVATION_REQUIRED" {
		t.Errorf("expected Code=ELEVATION_REQUIRED, got %q", elevErr.Code)
	}
}

func TestGuardCheck_WithActionEffect(t *testing.T) {
	var receivedBody ActionCheckRequest
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agenttrust/check": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&receivedBody)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"allowed": true})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	guard := NewGuard(c, "agent-1", WithActionEffect("read"))

	err := guard.Check(context.Background(), "list_files", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedBody.ActionEffect != "read" {
		t.Errorf("expected ActionEffect=read, got %q", receivedBody.ActionEffect)
	}
}

func TestGuardCheck_ElevationDenied_NoBlock(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agenttrust/check": jsonHandler(200, map[string]interface{}{
			"allowed":            false,
			"reason":             "needs elevation",
			"elevation_required": true,
			"approval_id":        "apr-002",
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	guard := NewGuard(c, "agent-1", WithBlockOnDeny(false))

	err := guard.Check(context.Background(), "write_file", "")
	if err != nil {
		t.Fatalf("expected nil with blockOnDeny=false, got: %v", err)
	}
}
