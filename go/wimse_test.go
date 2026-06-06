package agenttrust

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestWIMSEIssueToken(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/wimse/token": func(w http.ResponseWriter, r *http.Request) {
			var req IssueWIMSETokenRequest
			json.NewDecoder(r.Body).Decode(&req)
			if req.AgentID != "agent-1" {
				t.Errorf("expected agent_id=agent-1, got %q", req.AgentID)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(WIMSETokenResponse{
				Token:       "eyJ.wimse-token",
				WorkloadID:  "spiffe://agenttrust.id/agent/agent-1",
				TrustDomain: "agenttrust.id",
				ExpiresAt:   "2026-03-03T01:00:00Z",
			})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	resp, err := c.WIMSE.IssueToken(context.Background(), IssueWIMSETokenRequest{
		AgentID:     "agent-1",
		ServiceName: "data-processor",
		TTLSeconds:  600,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Token != "eyJ.wimse-token" {
		t.Errorf("expected token=eyJ.wimse-token, got %q", resp.Token)
	}
	if resp.TrustDomain != "agenttrust.id" {
		t.Errorf("expected trust_domain=agenttrust.id, got %q", resp.TrustDomain)
	}
	if resp.WorkloadID != "spiffe://agenttrust.id/agent/agent-1" {
		t.Errorf("expected SPIFFE URI, got %q", resp.WorkloadID)
	}
}

func TestWIMSEVerifyToken(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/wimse/verify": jsonHandler(200, VerifyWIMSETokenResponse{
			Valid:        true,
			AgentID:      "agent-1",
			WorkloadID:   "spiffe://agenttrust.id/agent/agent-1",
			TrustDomain:  "agenttrust.id",
			Capabilities: []string{"web_search", "files:read"},
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	resp, err := c.WIMSE.VerifyToken(context.Background(), VerifyWIMSETokenRequest{
		Token: "eyJ.wimse-token",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Error("expected valid=true")
	}
	if resp.AgentID != "agent-1" {
		t.Errorf("expected agent_id=agent-1, got %q", resp.AgentID)
	}
	if len(resp.Capabilities) != 2 {
		t.Errorf("expected 2 capabilities, got %d", len(resp.Capabilities))
	}
}

func TestWIMSEVerifyToken_Invalid(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/wimse/verify": jsonHandler(200, VerifyWIMSETokenResponse{
			Valid:  false,
			Reason: "token expired",
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	resp, err := c.WIMSE.VerifyToken(context.Background(), VerifyWIMSETokenRequest{
		Token: "eyJ.expired-token",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Valid {
		t.Error("expected valid=false")
	}
	if resp.Reason != "token expired" {
		t.Errorf("expected reason='token expired', got %q", resp.Reason)
	}
}
