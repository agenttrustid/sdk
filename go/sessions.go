package agenttrust

import (
	"context"
	"fmt"
	"net/http"
)

// SessionsAPI provides AgentTrust session management.
type SessionsAPI struct {
	client *Client
}

// InitSession creates a new AgentTrust session for an MCP server.
func (s *SessionsAPI) InitSession(ctx context.Context, req InitSessionRequest) (*Session, error) {
	var session Session
	if err := s.client.doRequest(ctx, http.MethodPost, "/mcp/sessions/init", req, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

// InitAPISession creates a new AgentTrust session from an AgentTrust ID API token.
func (s *SessionsAPI) InitAPISession(ctx context.Context, req InitAPISessionRequest) (*Session, error) {
	var session Session
	if err := s.client.doRequest(ctx, http.MethodPost, "/api/v1/agenttrust/api-sessions/init", req, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

// GetSession retrieves an existing session by ID.
func (s *SessionsAPI) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	var session Session
	path := fmt.Sprintf("/mcp/sessions/%s", sessionID)
	if err := s.client.doRequest(ctx, http.MethodGet, path, nil, &session); err != nil {
		return nil, err
	}
	return &session, nil
}
