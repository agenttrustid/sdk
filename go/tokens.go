package agenttrust

import (
	"context"
	"net/http"
)

// TokensAPI provides opaque agent token issuance, introspection, and revocation.
//
// Tokens are random opaque strings prefixed "at_" — not JWTs. They have no
// signature and cannot be validated client-side. To check a token, call
// (*TokensAPI).Introspect.
type TokensAPI struct {
	client *Client
}

// Issue creates a new opaque agent token (prefix "at_").
//
// The returned Token contains the opaque string in Token.Token to use in
// Authorization: Bearer headers. Tokens are short-lived (default 300 seconds)
// and scoped to specific permissions.
//
// Example:
//
//	token, err := client.Tokens.Issue(ctx, ati.IssueTokenRequest{
//	    AgentID:  agent.ID,
//	    Scope:    []string{"files:read"},
//	    TTL:      300,
//	})
//	// Use token.Token in requests:
//	//   Authorization: Bearer <token.Token>
func (t *TokensAPI) Issue(ctx context.Context, req IssueTokenRequest) (*Token, error) {
	if req.TTL == 0 {
		req.TTL = 300
	}
	if req.Scope == nil {
		req.Scope = []string{}
	}
	var resp issueTokenResponse
	if err := t.client.doRequest(ctx, http.MethodPost, "/api/v1/agent-tokens/issue", req, &resp); err != nil {
		return nil, err
	}
	return parseTokenFromResponse(&resp), nil
}

// Introspect sends a token to POST /api/v1/agent-tokens/introspect for
// server-side validation. Returns {active, agent_id, org_id, scopes,
// expires_at}.
//
// Example:
//
//	result, err := client.Tokens.Introspect(ctx, ati.IntrospectTokenRequest{
//	    Token:          token.Token,
//	    Target:         "mcp://filesystem",
//	    RequiredScopes: []string{"files:read"},
//	})
//	if result.Active {
//	    // Allow the operation
//	}
func (t *TokensAPI) Introspect(ctx context.Context, req IntrospectTokenRequest) (*IntrospectionResult, error) {
	if req.RequiredScopes == nil {
		req.RequiredScopes = []string{}
	}

	var resp IntrospectionResult
	if err := t.client.doRequest(ctx, http.MethodPost, "/api/v1/agent-tokens/introspect", req, &resp); err != nil {
		return nil, err
	}
	if resp.Scopes == nil {
		resp.Scopes = []string{}
	}
	return &resp, nil
}

// Verify is a deprecated alias for Introspect.
//
// Deprecated: Use (*TokensAPI).Introspect.
func (t *TokensAPI) Verify(ctx context.Context, req VerifyTokenRequest) (*VerificationResult, error) {
	return t.Introspect(ctx, req)
}

// Revoke immediately invalidates a specific opaque agent token.
func (t *TokensAPI) Revoke(ctx context.Context, token string, reason string) error {
	if reason == "" {
		reason = "manual_revocation"
	}
	return t.client.doRequest(ctx, http.MethodPost, "/api/v1/agent-tokens/revoke", revokeTokenRequest{
		Token:  token,
		Reason: reason,
	}, nil)
}
