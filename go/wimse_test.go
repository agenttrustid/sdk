package agenttrust

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
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

// TestWIMSEIssueTokenWithProof verifies the SDK performs the full
// challenge -> sign -> issue flow and that the proof it sends is a valid Ed25519
// signature over the canonical message the server expects.
func TestWIMSEIssueTokenWithProof(t *testing.T) {
	key, err := GenerateAgentKey()
	if err != nil {
		t.Fatalf("GenerateAgentKey: %v", err)
	}
	ks := NewMemoryKeyStore()
	if err := ks.Store("agent-1", key.PrivateKeyPEM); err != nil {
		t.Fatalf("Store: %v", err)
	}

	const nonce = "server-nonce-xyz"
	audience := []string{"https://api.example.com"}
	var gotProof *PoPProof

	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/agents/agent-1/challenge": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ChallengeResponse{Nonce: nonce, ExpiresAt: "2026-03-03T01:00:00Z"})
		},
		"POST /api/v1/wimse/token": func(w http.ResponseWriter, r *http.Request) {
			var req IssueWIMSETokenRequest
			json.NewDecoder(r.Body).Decode(&req)
			gotProof = req.Proof
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(WIMSETokenResponse{Token: "eyJ.bound", TrustDomain: "agenttrust.id"})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	resp, err := c.WIMSE.IssueTokenWithProof(context.Background(), IssueWIMSETokenRequest{
		AgentID:  "agent-1",
		Audience: audience,
	}, ks)
	if err != nil {
		t.Fatalf("IssueTokenWithProof: %v", err)
	}
	if resp.Token != "eyJ.bound" {
		t.Errorf("token = %q", resp.Token)
	}
	if gotProof == nil {
		t.Fatal("server did not receive a proof")
	}
	if gotProof.Nonce != nonce {
		t.Errorf("proof nonce = %q, want %q", gotProof.Nonce, nonce)
	}

	// The signature must verify against the canonical message with the agent's
	// public key — exactly what the server's VerifyPoP does.
	priv, err := parsePrivateKeyPEM(key.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	sig, err := base64.RawURLEncoding.DecodeString(gotProof.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	msg := []byte("pop-v1:" + nonce + ":agent-1:" + strings.Join(audience, ",") + ":" + strconv.FormatInt(gotProof.Timestamp, 10))
	if !ed25519.Verify(pub, msg, sig) {
		t.Error("proof signature did not verify against canonical message")
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
