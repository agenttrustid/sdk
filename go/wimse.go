package agenttrust

import (
	"context"
	"net/http"
)

// WIMSEAPI provides WIMSE workload identity token operations.
type WIMSEAPI struct {
	client *Client
}

// IssueWIMSETokenRequest contains the parameters for issuing a WIMSE token.
type IssueWIMSETokenRequest struct {
	AgentID     string `json:"agent_id"`
	ServiceName string `json:"service_name,omitempty"`
	Environment string `json:"environment,omitempty"`
	TTLSeconds  int    `json:"ttl_seconds,omitempty"`
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

// VerifyToken verifies a WIMSE workload identity token.
func (w *WIMSEAPI) VerifyToken(ctx context.Context, req VerifyWIMSETokenRequest) (*VerifyWIMSETokenResponse, error) {
	var resp VerifyWIMSETokenResponse
	if err := w.client.doRequest(ctx, http.MethodPost, "/api/v1/wimse/verify", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
