package agenttrust

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestFederationRegisterProvider(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/federation/providers": func(w http.ResponseWriter, r *http.Request) {
			var req RegisterProviderRequest
			json.NewDecoder(r.Body).Decode(&req)
			if req.Issuer != "https://other-realm.example.com" {
				t.Errorf("expected issuer=https://other-realm.example.com, got %q", req.Issuer)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"provider": FederationProvider{
					ID:     "prov-1",
					Issuer: req.Issuer,
					Name:   req.Name,
					Status: "active",
				},
			})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	resp, err := c.Federation.RegisterProvider(context.Background(), RegisterProviderRequest{
		Issuer: "https://other-realm.example.com",
		Name:   "Other Realm",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ID != "prov-1" {
		t.Errorf("expected id=prov-1, got %q", resp.ID)
	}
	if resp.Status != "active" {
		t.Errorf("expected status=active, got %q", resp.Status)
	}
}

func TestFederationListProviders(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"GET /api/v1/federation/providers": jsonHandler(200, federationProviderListResponse{
			Providers: []FederationProvider{
				{ID: "prov-1", Issuer: "https://a.example.com", Name: "Provider A", Status: "active"},
				{ID: "prov-2", Issuer: "https://b.example.com", Name: "Provider B", Status: "active"},
			},
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	providers, err := c.Federation.ListProviders(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(providers) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(providers))
	}
	if providers[0].Name != "Provider A" {
		t.Errorf("expected first provider name=Provider A, got %q", providers[0].Name)
	}
}

func TestFederationDeleteProvider(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"DELETE /api/v1/federation/providers/prov-1": jsonHandler(200, map[string]string{"status": "deleted"}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	err := c.Federation.DeleteProvider(context.Background(), "prov-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFederationIssueIDToken(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/federation/tokens/issue": jsonHandler(201, IssueIDTokenResponse{
			IDToken:   "eyJhbGciOiJFZERTQSJ9.test",
			ExpiresIn: 300,
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	resp, err := c.Federation.IssueIDToken(context.Background(), "agent-1", IssueIDTokenRequest{
		Audience: "https://resource.example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IDToken != "eyJhbGciOiJFZERTQSJ9.test" {
		t.Errorf("expected id_token to start with eyJ, got %q", resp.IDToken)
	}
	if resp.ExpiresIn != 300 {
		t.Errorf("expected expires_in=300, got %d", resp.ExpiresIn)
	}
}

func TestFederationVerifyToken(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/federation/tokens/verify": jsonHandler(200, VerifyFederatedTokenResponse{
			Valid:   true,
			Issuer:  "https://other.example.com",
			AgentID: "agent-remote-1",
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	resp, err := c.Federation.VerifyToken(context.Background(), VerifyFederatedTokenRequest{
		Token: "eyJ.federated-token",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Error("expected valid=true")
	}
	if resp.AgentID != "agent-remote-1" {
		t.Errorf("expected agent_id=agent-remote-1, got %q", resp.AgentID)
	}
}

func TestFederationInitSession(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/federation/sessions/init": func(w http.ResponseWriter, r *http.Request) {
			var req InitFederatedSessionRequest
			json.NewDecoder(r.Body).Decode(&req)
			if req.Token != "eyJ.federated-token" {
				t.Errorf("expected token=eyJ.federated-token, got %q", req.Token)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"session_id":    "sess-fed-001",
				"agent_id":      "agent-remote-1",
				"provider_id":   "prov-1",
				"issuer":        "https://other.example.com",
				"trust_level":   "high",
				"mode":          "read_only",
				"scope_ceiling": []string{"federation:invoke"},
				"source":        "federation",
			})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	session, err := c.Federation.InitSession(context.Background(), InitFederatedSessionRequest{
		Token: "eyJ.federated-token",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session.SessionID != "sess-fed-001" {
		t.Errorf("expected SessionID=sess-fed-001, got %q", session.SessionID)
	}
	if session.ProviderID != "prov-1" {
		t.Errorf("expected ProviderID=prov-1, got %q", session.ProviderID)
	}
	if session.TrustLevel != "high" {
		t.Errorf("expected TrustLevel=high, got %q", session.TrustLevel)
	}
}
