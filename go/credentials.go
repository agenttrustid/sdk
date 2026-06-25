package agenttrust

import (
	"context"
	"sync"
	"time"
)

// credentialRefreshSkew is how long before a WIMSE token's expiry the manager
// proactively re-issues, so a request never goes out with an about-to-expire token.
const credentialRefreshSkew = 60 * time.Second

// AgentCredentials manages an agent's runtime authentication: it auto-issues a
// WIMSE token via the proof-of-possession flow, caches it, refreshes it before
// expiry, and produces per-request `Authorization: Bearer` + `DPoP` headers. The
// private key never leaves the KeyStore — both the PoP signature (at issuance)
// and the DPoP proof (per request) are signed through it.
//
// It is safe for concurrent use.
type AgentCredentials struct {
	wimse        *WIMSEAPI
	baseURL      string
	ks           KeyStore
	agentID      string
	publicKeyPEM string
	audience     []string
	ttlSeconds   int

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// CredentialOption configures an AgentCredentials.
type CredentialOption func(*AgentCredentials)

// WithCredentialAudience sets the WIMSE token audience.
func WithCredentialAudience(audience ...string) CredentialOption {
	return func(ac *AgentCredentials) { ac.audience = audience }
}

// WithCredentialTTL sets the requested WIMSE token TTL in seconds (0 = server default).
func WithCredentialTTL(seconds int) CredentialOption {
	return func(ac *AgentCredentials) { ac.ttlSeconds = seconds }
}

// NewAgentCredentials builds a credential manager for an agent. publicKeyPEM is
// the agent's registered public key (used to populate DPoP proofs); the matching
// private key must be held in ks under agentID.
func NewAgentCredentials(c *Client, ks KeyStore, agentID, publicKeyPEM string, opts ...CredentialOption) *AgentCredentials {
	ac := &AgentCredentials{
		wimse:        c.WIMSE,
		baseURL:      c.baseURL,
		ks:           ks,
		agentID:      agentID,
		publicKeyPEM: publicKeyPEM,
	}
	for _, opt := range opts {
		opt(ac)
	}
	return ac
}

// Token returns a currently-valid WIMSE token, issuing or refreshing one via the
// proof-of-possession flow when the cache is empty or near expiry.
func (ac *AgentCredentials) Token(ctx context.Context) (string, error) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if ac.token != "" && time.Until(ac.expiresAt) > credentialRefreshSkew {
		return ac.token, nil
	}

	resp, err := ac.wimse.IssueTokenWithProof(ctx, IssueWIMSETokenRequest{
		AgentID:    ac.agentID,
		Audience:   ac.audience,
		TTLSeconds: ac.ttlSeconds,
	}, ac.ks)
	if err != nil {
		return "", err
	}
	ac.token = resp.Token
	ac.expiresAt = parseTokenExpiry(resp.ExpiresAt)
	return ac.token, nil
}

// RuntimeHeaders returns the headers to attach to a runtime request for the given
// method and request path: a Bearer WIMSE token plus a fresh DPoP proof bound to
// the request (htu = the client's base URL + path) and the token (ath).
func (ac *AgentCredentials) RuntimeHeaders(ctx context.Context, method, path string) (map[string]string, error) {
	token, err := ac.Token(ctx)
	if err != nil {
		return nil, err
	}
	proof, err := MintDPoPProofWithKeyStore(ac.ks, ac.agentID, ac.publicKeyPEM, method, ac.baseURL+path, token)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"Authorization": "Bearer " + token,
		"DPoP":          proof,
	}, nil
}

// Invalidate clears the cached token, forcing a fresh issuance on the next call.
// Call this after a 401 so a revoked/expired token is replaced.
func (ac *AgentCredentials) Invalidate() {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.token = ""
	ac.expiresAt = time.Time{}
}

// parseTokenExpiry parses an RFC 3339 expiry; on failure it falls back to a
// conservative short window so the manager re-issues soon rather than trusting an
// unparseable value.
func parseTokenExpiry(s string) time.Time {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Now().Add(5 * time.Minute)
}
