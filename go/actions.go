package agenttrust

import (
	"context"
	"net/http"
)

// ActionsAPI provides pre-flight action authorization checks.
//
// Use this API to check whether an agent is authorized to perform a specific
// tool call before executing it. The Fast Guard check typically completes in
// under 15 milliseconds.
type ActionsAPI struct {
	client *Client
}

// Check performs a pre-flight authorization check for a tool call.
//
// The tool input summary is automatically truncated to 200 characters for privacy.
//
// Example:
//
//	result, err := client.Actions.Check(ctx, ati.ActionCheckRequest{
//	    AgentID:          agent.ID,
//	    ToolName:         "web_search",
//	    ToolInputSummary: "latest AI research papers",
//	    SessionID:        sessionID,
//	})
//	if result.Allowed {
//	    // Execute the tool call
//	}
func (a *ActionsAPI) Check(ctx context.Context, req ActionCheckRequest) (*ActionCheckResult, error) {
	if req.Action == "" {
		req.Action = "tool_call"
	}
	actionName := req.ToolName
	if actionName == "" {
		actionName = req.Action
	}

	// Truncate tool input summary for privacy
	if len(req.ToolInputSummary) > 200 {
		req.ToolInputSummary = req.ToolInputSummary[:200]
	}

	body := agentTrustActionCheckRequest{
		AgentID:            req.AgentID,
		SessionID:          req.SessionID,
		ActionName:         actionName,
		ActionEffect:       req.ActionEffect,
		ActionSource:       "api",
		ActionInputSummary: req.ToolInputSummary,
	}

	var resp ActionCheckResult
	if err := a.client.doRequest(ctx, http.MethodPost, "/api/v1/agenttrust/check", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type agentTrustActionCheckRequest struct {
	AgentID            string `json:"agent_id"`
	SessionID          string `json:"session_id,omitempty"`
	ActionName         string `json:"action_name"`
	ActionEffect       string `json:"action_effect,omitempty"`
	ActionSource       string `json:"action_source"`
	ActionInputSummary string `json:"action_input_summary,omitempty"`
}
