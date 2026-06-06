package agenttrust

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestDelegationsCreate(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/delegations": func(w http.ResponseWriter, r *http.Request) {
			var req CreateDelegationRequest
			json.NewDecoder(r.Body).Decode(&req)
			if req.FromAgentID != "agent-a" {
				t.Errorf("expected from_agent_id=agent-a, got %q", req.FromAgentID)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"delegation": Delegation{
					ID:              "del-001",
					FromAgentID:     req.FromAgentID,
					ToAgentID:       req.ToAgentID,
					Scope:           req.Scope,
					DelegationChain: []string{"root-del"},
					CreatedAt:       "2026-03-01T10:00:00Z",
					ExpiresAt:       "2026-03-01T11:00:00Z",
				},
			})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	delegation, err := c.Delegations.Create(context.Background(), CreateDelegationRequest{
		FromAgentID: "agent-a",
		ToAgentID:   "agent-b",
		Scope:       []string{"files:read"},
		TTLSeconds:  3600,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if delegation.ID != "del-001" {
		t.Errorf("expected ID=del-001, got %q", delegation.ID)
	}
	if delegation.ToAgentID != "agent-b" {
		t.Errorf("expected ToAgentID=agent-b, got %q", delegation.ToAgentID)
	}
}

func TestDelegationsList(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"GET /api/v1/delegations": jsonHandler(200, map[string]interface{}{
			"delegations": []Delegation{
				{ID: "del-001", FromAgentID: "agent-a", ToAgentID: "agent-b", Scope: []string{"files:read"}},
				{ID: "del-002", FromAgentID: "agent-c", ToAgentID: "agent-d", Scope: []string{"web:fetch"}},
			},
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	delegations, err := c.Delegations.List(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(delegations) != 2 {
		t.Fatalf("expected 2 delegations, got %d", len(delegations))
	}
}

func TestDelegationsRevoke(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"DELETE /api/v1/delegations/del-001": jsonHandler(200, map[string]string{"status": "revoked"}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	if err := c.Delegations.Revoke(context.Background(), "del-001"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDelegationsInitSession(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/delegations/del-001/session": jsonHandler(201, map[string]interface{}{
			"session_id":    "sess-del-001",
			"agent_id":      "agent-b",
			"delegation_id": "del-001",
			"mode":          "read_only",
			"scope_ceiling": []string{"files:read"},
			"source":        "a2a",
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	session, err := c.Delegations.InitSession(context.Background(), "del-001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session.DelegationID != "del-001" {
		t.Errorf("expected DelegationID=del-001, got %q", session.DelegationID)
	}
	if session.Source != "a2a" {
		t.Errorf("expected Source=a2a, got %q", session.Source)
	}
}
