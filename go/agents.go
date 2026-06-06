package agenttrust

import (
	"context"
	"fmt"
	"net/http"
)

// AgentsAPI provides agent registration and lifecycle management.
//
// Agents are the core identity primitive in ATI. The platform does not issue
// certificates; use TokensAPI.Issue to mint opaque "at_" tokens for an agent.
type AgentsAPI struct {
	client *Client
}

// Create registers a new agent with the AgentTrust ID identity service.
//
// The returned Agent has a PrivateKey only when the platform supplies one
// (it can also be generated client-side and registered separately). The
// platform does not issue certificates.
//
// Example:
//
//	agent, err := client.Agents.Create(ctx, ati.CreateAgentRequest{
//	    Name:         "my-assistant",
//	    Framework:    "langchain",
//	    Capabilities: []string{"files:read", "web:fetch"},
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
func (a *AgentsAPI) Create(ctx context.Context, req CreateAgentRequest) (*Agent, error) {
	framework := req.Framework
	if framework == "" {
		framework = "custom"
	}
	caps := req.Capabilities
	if caps == nil {
		caps = []string{}
	}
	meta := req.Metadata
	if meta == nil {
		meta = map[string]interface{}{}
	}

	apiReq := createAgentAPIRequest{
		Name:         req.Name,
		Framework:    framework,
		Capabilities: caps,
		Metadata:     meta,
		OrgID:        req.OrgID,
	}

	var resp createAgentResponse
	if err := a.client.doRequest(ctx, http.MethodPost, "/api/v1/agents", apiReq, &resp); err != nil {
		return nil, err
	}

	// The API may return the agent data in a nested "agent" field or at the top level.
	if resp.Agent != nil {
		return parseAgentFromData(resp.Agent), nil
	}

	// Flat response: construct agentData from top-level fields
	ad := &agentData{
		ID:           resp.ID,
		Name:         resp.Name,
		OrgID:        resp.OrgID,
		Framework:    resp.Framework,
		PublicKey:    resp.PublicKey,
		Status:       resp.Status,
		Capabilities: resp.Capabilities,
		Metadata:     resp.Metadata,
		CreatedAt:    resp.CreatedAt,
		PrivateKey:   resp.PrivateKey,
	}
	return parseAgentFromData(ad), nil
}

// Get retrieves an agent by its ID.
//
// Returns a NotFoundError if the agent does not exist.
func (a *AgentsAPI) Get(ctx context.Context, agentID string) (*Agent, error) {
	var resp agentData
	path := fmt.Sprintf("/api/v1/agents/%s", agentID)
	if err := a.client.doRequest(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return parseAgentFromData(&resp), nil
}

// List retrieves all agents, optionally filtered by organization ID.
//
// Pass an empty string for orgID to list all agents.
func (a *AgentsAPI) List(ctx context.Context, orgID string) ([]*Agent, error) {
	path := "/api/v1/agents"
	if orgID != "" {
		path += "?org_id=" + orgID
	}

	var resp agentListResponse
	if err := a.client.doRequest(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}

	agents := make([]*Agent, 0, len(resp.Agents))
	for i := range resp.Agents {
		agents = append(agents, parseAgentFromData(&resp.Agents[i]))
	}
	return agents, nil
}

// Revoke permanently revokes an agent and all its tokens.
//
// This action is immediate and cannot be undone.
func (a *AgentsAPI) Revoke(ctx context.Context, agentID string, reason string) error {
	if reason == "" {
		reason = "manual_revocation"
	}
	path := fmt.Sprintf("/api/v1/agents/%s/revoke", agentID)
	return a.client.doRequest(ctx, http.MethodPost, path, revokeRequest{Reason: reason}, nil)
}
