package agenttrust

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func challengeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"nonce":      "nonce-123",
			"expires_at": time.Now().Add(time.Minute).Format(time.RFC3339),
		})
	}
}

func tokenHandler(expiry time.Time, calls *int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		*calls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token":      "wimse-tok",
			"expires_at": expiry.Format(time.RFC3339),
		})
	}
}

func credsFixture(t *testing.T) (*MemoryKeyStore, AgentKeyPair) {
	t.Helper()
	kp, err := GenerateAgentKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	ks := NewMemoryKeyStore()
	if err := ks.Store("agent-1", kp.PrivateKeyPEM); err != nil {
		t.Fatalf("store: %v", err)
	}
	return ks, kp
}

func TestAgentCredentials_IssuesCachesAndMintsHeaders(t *testing.T) {
	var tokenCalls int
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agents/agent-1/challenge": challengeHandler(),
		"POST /api/v1/wimse/token":              tokenHandler(time.Now().Add(time.Hour), &tokenCalls),
	})
	defer srv.Close()

	ks, kp := credsFixture(t)
	ac := NewAgentCredentials(NewClient(WithBaseURL(srv.URL)), ks, "agent-1", kp.PublicKeyPEM)

	tok, err := ac.Token(context.Background())
	if err != nil || tok != "wimse-tok" {
		t.Fatalf("Token = %q, err = %v", tok, err)
	}
	// Cached (valid ~1h) — second call must not re-issue.
	if _, err := ac.Token(context.Background()); err != nil {
		t.Fatalf("second Token: %v", err)
	}
	if tokenCalls != 1 {
		t.Errorf("tokenCalls = %d, want 1 (cached)", tokenCalls)
	}

	h, err := ac.RuntimeHeaders(context.Background(), "POST", "/api/v1/agenttrust/check")
	if err != nil {
		t.Fatalf("RuntimeHeaders: %v", err)
	}
	if h["Authorization"] != "Bearer wimse-tok" {
		t.Errorf("Authorization = %q", h["Authorization"])
	}
	if h["DPoP"] == "" {
		t.Error("missing DPoP header")
	}
}

func TestAgentCredentials_RefreshesNearExpiry(t *testing.T) {
	var tokenCalls int
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agents/agent-1/challenge": challengeHandler(),
		// Expires in 10s — inside the 60s refresh skew — so each Token() re-issues.
		"POST /api/v1/wimse/token": tokenHandler(time.Now().Add(10*time.Second), &tokenCalls),
	})
	defer srv.Close()

	ks, kp := credsFixture(t)
	ac := NewAgentCredentials(NewClient(WithBaseURL(srv.URL)), ks, "agent-1", kp.PublicKeyPEM)

	if _, err := ac.Token(context.Background()); err != nil {
		t.Fatalf("first Token: %v", err)
	}
	if _, err := ac.Token(context.Background()); err != nil {
		t.Fatalf("second Token: %v", err)
	}
	if tokenCalls != 2 {
		t.Errorf("tokenCalls = %d, want 2 (re-issue near expiry)", tokenCalls)
	}
}

func TestAgentCredentials_CheckAttachesBearerAndDPoP(t *testing.T) {
	var tokenCalls int
	var gotAuth, gotDPoP string
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agents/agent-1/challenge": challengeHandler(),
		"POST /api/v1/wimse/token":              tokenHandler(time.Now().Add(time.Hour), &tokenCalls),
		"POST /api/v1/agenttrust/check": func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			gotDPoP = r.Header.Get("DPoP")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"allowed": true, "guard_tier": "fast"})
		},
	})
	defer srv.Close()

	ks, kp := credsFixture(t)
	ac := NewAgentCredentials(NewClient(WithBaseURL(srv.URL)), ks, "agent-1", kp.PublicKeyPEM)
	c := NewClient(WithBaseURL(srv.URL), WithAgentCredentials(ac))

	if _, err := c.Actions.Check(context.Background(), ActionCheckRequest{AgentID: "agent-1", ToolName: "read_file"}); err != nil {
		t.Fatalf("check: %v", err)
	}
	if gotAuth != "Bearer wimse-tok" {
		t.Errorf("Authorization = %q, want Bearer wimse-tok", gotAuth)
	}
	if gotDPoP == "" {
		t.Error("check request missing DPoP header")
	}
}
