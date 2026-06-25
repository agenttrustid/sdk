package agenttrust

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// WIMSEAPI provides WIMSE workload identity token operations.
type WIMSEAPI struct {
	client *Client
}

// IssueWIMSETokenRequest contains the parameters for issuing a WIMSE token.
type IssueWIMSETokenRequest struct {
	AgentID     string   `json:"agent_id"`
	ServiceName string   `json:"service_name,omitempty"`
	Environment string   `json:"environment,omitempty"`
	TTLSeconds  int      `json:"ttl_seconds,omitempty"`
	Audience    []string `json:"audience,omitempty"`

	// Proof, when set, carries a proof-of-possession over a server challenge.
	// Prefer IssueTokenWithProof, which populates this for you.
	Proof *PoPProof `json:"proof,omitempty"`
}

// PoPProof is a proof-of-possession: an Ed25519 signature over a server-issued
// challenge nonce, proving the agent holds the private key matching its
// registered public key. A valid proof binds the issued token to that key via
// the token's RFC 7800 cnf.jkt claim.
type PoPProof struct {
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"ts"`
	Signature string `json:"signature"`
}

// ChallengeResponse is the server's reply to a proof-of-possession challenge.
type ChallengeResponse struct {
	Nonce     string `json:"nonce"`
	ExpiresAt string `json:"expires_at"`
}

// popMessage builds the canonical proof-of-possession message that the agent
// signs and the server verifies. It must stay byte-identical to the server's
// crypto.PoPMessage: "pop-v1:<nonce>:<agentID>:<audience>:<ts>", where audience
// is the comma-joined request audience (in request order) and ts is the signing
// time in unix seconds.
func popMessage(nonce, agentID, audience string, ts int64) []byte {
	return []byte(fmt.Sprintf("pop-v1:%s:%s:%s:%d", nonce, agentID, audience, ts))
}

// WIMSETokenResponse contains the result of issuing a WIMSE token.
type WIMSETokenResponse struct {
	Token       string `json:"token"`
	WorkloadID  string `json:"workload_id"`
	TrustDomain string `json:"trust_domain"`
	ExpiresAt   string `json:"expires_at"`
}

// VerifyWIMSETokenRequest contains the parameters for verifying a WIMSE token.
type VerifyWIMSETokenRequest struct {
	Token             string `json:"token"`
	TrustDomainFilter string `json:"trust_domain_filter,omitempty"`
}

// VerifyWIMSETokenResponse contains the result of verifying a WIMSE token.
type VerifyWIMSETokenResponse struct {
	Valid        bool     `json:"valid"`
	AgentID      string   `json:"agent_id,omitempty"`
	WorkloadID   string   `json:"workload_id,omitempty"`
	TrustDomain  string   `json:"trust_domain,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Reason       string   `json:"reason,omitempty"`
}

// IssueToken issues a WIMSE workload identity token.
func (w *WIMSEAPI) IssueToken(ctx context.Context, req IssueWIMSETokenRequest) (*WIMSETokenResponse, error) {
	var resp WIMSETokenResponse
	if err := w.client.doRequest(ctx, http.MethodPost, "/api/v1/wimse/token", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Challenge requests a single-use proof-of-possession nonce for an agent.
func (w *WIMSEAPI) Challenge(ctx context.Context, agentID string) (*ChallengeResponse, error) {
	var resp ChallengeResponse
	if err := w.client.doRequest(ctx, http.MethodPost, "/api/v1/agents/"+agentID+"/challenge", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// IssueTokenWithProof issues a WIMSE token using proof-of-possession. It fetches
// a challenge for the agent, signs the canonical challenge message with the
// agent's key from ks, and issues with the proof attached so the resulting token
// is bound to the agent key (cnf.jkt). Use this whenever the agent has a
// registered key — it is required when the org enables proof-of-possession.
func (w *WIMSEAPI) IssueTokenWithProof(ctx context.Context, req IssueWIMSETokenRequest, ks KeyStore) (*WIMSETokenResponse, error) {
	if ks == nil {
		return nil, fmt.Errorf("a KeyStore is required for proof-of-possession")
	}
	challenge, err := w.Challenge(ctx, req.AgentID)
	if err != nil {
		return nil, fmt.Errorf("proof-of-possession challenge: %w", err)
	}
	ts := time.Now().Unix()
	audience := strings.Join(req.Audience, ",")
	sig, err := ks.Sign(req.AgentID, popMessage(challenge.Nonce, req.AgentID, audience, ts))
	if err != nil {
		return nil, fmt.Errorf("sign proof-of-possession challenge: %w", err)
	}
	req.Proof = &PoPProof{
		Nonce:     challenge.Nonce,
		Timestamp: ts,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
	return w.IssueToken(ctx, req)
}

// VerifyToken verifies a WIMSE workload identity token.
func (w *WIMSEAPI) VerifyToken(ctx context.Context, req VerifyWIMSETokenRequest) (*VerifyWIMSETokenResponse, error) {
	var resp VerifyWIMSETokenResponse
	if err := w.client.doRequest(ctx, http.MethodPost, "/api/v1/wimse/verify", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
