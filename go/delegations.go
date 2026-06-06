package agenttrust

import (
	"context"
	"fmt"
	"net/http"
)

// DelegationsAPI provides agent-to-agent delegation management.
type DelegationsAPI struct {
	client *Client
}

type delegationCreateResponse struct {
	Delegation Delegation `json:"delegation"`
}

type delegationListResponse struct {
	Delegations []Delegation `json:"delegations"`
}

// Create creates a new delegation from one agent to another.
func (d *DelegationsAPI) Create(ctx context.Context, req CreateDelegationRequest) (*Delegation, error) {
	var resp delegationCreateResponse
	if err := d.client.doRequest(ctx, http.MethodPost, "/api/v1/delegations", req, &resp); err != nil {
		return nil, err
	}
	return &resp.Delegation, nil
}

// List lists all delegations for the current organization.
func (d *DelegationsAPI) List(ctx context.Context) ([]Delegation, error) {
	var resp delegationListResponse
	if err := d.client.doRequest(ctx, http.MethodGet, "/api/v1/delegations", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Delegations, nil
}

// Revoke revokes a delegation immediately.
func (d *DelegationsAPI) Revoke(ctx context.Context, delegationID string) error {
	path := fmt.Sprintf("/api/v1/delegations/%s", delegationID)
	return d.client.doRequest(ctx, http.MethodDelete, path, nil, nil)
}

// InitSession creates an AgentTrust session from an existing delegation.
func (d *DelegationsAPI) InitSession(ctx context.Context, delegationID string) (*Session, error) {
	var session Session
	path := fmt.Sprintf("/api/v1/delegations/%s/session", delegationID)
	if err := d.client.doRequest(ctx, http.MethodPost, path, nil, &session); err != nil {
		return nil, err
	}
	return &session, nil
}
