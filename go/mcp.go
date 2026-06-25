package agenttrust

import (
	"context"
	"fmt"
	"net/http"
)

// MCPAPI provides MCP proxy tool-calling through the AgentTrust ID gateway.
type MCPAPI struct {
	client *Client
}

// CallTool calls a tool on a registered MCP server through the AgentTrust ID proxy.
//
// The proxy enforces Guardian policy before forwarding the JSON-RPC request to
// the target MCP server. The proxy authorizes the call by agent identity, so
// agentID is required and is sent as the X-Agent-ID header — the gateway rejects
// the request without it. When sessionID is non-empty it is sent as X-Session-ID
// for session-scoped authorization.
//
// It returns the JSON-RPC "result" object on success, or the full response map
// if no "result" field is present.
func (m *MCPAPI) CallTool(ctx context.Context, serverID, agentID, method string, params map[string]interface{}, sessionID string) (map[string]interface{}, error) {
	if agentID == "" {
		return nil, &AgentTrustError{
			Message: "agentID is required: the MCP proxy authorizes the call by agent identity (X-Agent-ID)",
			Code:    "INVALID_ARGUMENT",
		}
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
	}
	if params != nil {
		payload["params"] = params
	}

	headers := map[string]string{"X-Agent-ID": agentID}
	if sessionID != "" {
		headers["X-Session-ID"] = sessionID
	}

	var resp map[string]interface{}
	path := fmt.Sprintf("/mcp/%s", serverID)
	if err := m.client.doRequestWithHeaders(ctx, http.MethodPost, path, payload, &resp, headers); err != nil {
		return nil, err
	}

	if raw, ok := resp["result"]; ok {
		if result, ok := raw.(map[string]interface{}); ok {
			return result, nil
		}
	}
	return resp, nil
}
