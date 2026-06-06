package agenttrust

import (
	"context"
	"fmt"
	"net/http"
)

// FederationAPI provides OIDC federation operations.
type FederationAPI struct {
	client *Client
}

// FederationProvider represents an OIDC federation provider.
type FederationProvider struct {
	ID                    string `json:"id"`
	OrgID                 string `json:"org_id"`
	Issuer                string `json:"issuer"`
	Name                  string `json:"name"`
	JWKSUri               string `json:"jwks_uri"`
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string `json:"token_endpoint,omitempty"`
	TrustLevel            string `json:"trust_level"`
	Status                string `json:"status"`
	CreatedAt             string `json:"created_at,omitempty"`
	UpdatedAt             string `json:"updated_at,omitempty"`
}

// RegisterProviderRequest contains the parameters for registering a federation provider.
type RegisterProviderRequest struct {
	Issuer     string `json:"issuer"`
	Name       string `json:"name"`
	TrustLevel string `json:"trust_level,omitempty"`
}

// VerifyFederatedTokenRequest contains the parameters for verifying a federated token.
type VerifyFederatedTokenRequest struct {
	Token      string `json:"token"`
	IssuerHint string `json:"issuer_hint,omitempty"`
}

// VerifyFederatedTokenResponse contains the result of verifying a federated token.
type VerifyFederatedTokenResponse struct {
	Valid     bool   `json:"valid"`
	AgentID   string `json:"agent_id,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

// IssueIDTokenRequest contains the parameters for issuing an opaque
// federation token.
type IssueIDTokenRequest struct {
	Audience string   `json:"audience,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
	// Nonce is retained for source compatibility and is not sent to the
	// opaque federation token endpoint.
	//
	// Deprecated: AgentTrust no longer issues OIDC ID tokens.
	Nonce string `json:"-"`
	TTL   int    `json:"ttl,omitempty"`
}

// IssueIDTokenResponse contains the result of issuing an opaque federation
// token. IDToken is populated with the same opaque token string for backwards
// compatibility with earlier SDK versions.
type IssueIDTokenResponse struct {
	IDToken   string `json:"id_token"`
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// InitFederatedSessionRequest contains the parameters for verifying a
// federated token and bridging it into a local AgentTrust session.
type InitFederatedSessionRequest struct {
	Token      string `json:"token"`
	IssuerHint string `json:"issuer_hint,omitempty"`
}

// federationProviderListResponse wraps the list response.
type federationProviderListResponse struct {
	Providers []FederationProvider `json:"providers"`
}

type federationRegisterProviderResponse struct {
	Provider FederationProvider `json:"provider"`
}

// RegisterProvider registers a new OIDC federation provider.
func (f *FederationAPI) RegisterProvider(ctx context.Context, req RegisterProviderRequest) (*FederationProvider, error) {
	var resp federationRegisterProviderResponse
	if err := f.client.doRequest(ctx, http.MethodPost, "/api/v1/federation/providers", req, &resp); err != nil {
		return nil, err
	}
	return &resp.Provider, nil
}

// ListProviders lists all active federation providers.
func (f *FederationAPI) ListProviders(ctx context.Context) ([]FederationProvider, error) {
	var resp federationProviderListResponse
	if err := f.client.doRequest(ctx, http.MethodGet, "/api/v1/federation/providers", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Providers, nil
}

// DeleteProvider removes a federation provider.
func (f *FederationAPI) DeleteProvider(ctx context.Context, providerID string) error {
	path := fmt.Sprintf("/api/v1/federation/providers/%s", providerID)
	return f.client.doRequest(ctx, http.MethodDelete, path, nil, nil)
}

// IssueIDToken issues an opaque federation token for an agent.
//
// Deprecated: AgentTrust does not issue OIDC ID tokens. Use this only as a
// compatibility wrapper around POST /api/v1/federation/tokens/issue.
func (f *FederationAPI) IssueIDToken(ctx context.Context, agentID string, req IssueIDTokenRequest) (*IssueIDTokenResponse, error) {
	var resp IssueIDTokenResponse
	body := issueFederationTokenRequest{
		AgentID:  agentID,
		Audience: req.Audience,
		Scopes:   req.Scopes,
		TTL:      req.TTL,
	}
	if err := f.client.doRequest(ctx, http.MethodPost, "/api/v1/federation/tokens/issue", body, &resp); err != nil {
		return nil, err
	}
	if resp.IDToken == "" {
		resp.IDToken = resp.Token
	}
	if resp.Token == "" {
		resp.Token = resp.IDToken
	}
	return &resp, nil
}

type issueFederationTokenRequest struct {
	AgentID  string   `json:"agent_id"`
	Audience string   `json:"audience,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
	TTL      int      `json:"ttl,omitempty"`
}

// VerifyToken verifies a federated token.
func (f *FederationAPI) VerifyToken(ctx context.Context, req VerifyFederatedTokenRequest) (*VerifyFederatedTokenResponse, error) {
	var resp VerifyFederatedTokenResponse
	if err := f.client.doRequest(ctx, http.MethodPost, "/api/v1/federation/tokens/verify", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// InitSession verifies a federated token and creates a local AgentTrust session.
func (f *FederationAPI) InitSession(ctx context.Context, req InitFederatedSessionRequest) (*Session, error) {
	var resp Session
	if err := f.client.doRequest(ctx, http.MethodPost, "/api/v1/federation/sessions/init", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
