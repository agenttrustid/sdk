package agenttrust

import (
	"context"
	"fmt"
	"net/http"
)

// ApprovalsAPI provides AgentTrust elevation approval management.
type ApprovalsAPI struct {
	client *Client
}

// Approve approves a pending elevation request.
func (a *ApprovalsAPI) Approve(ctx context.Context, approvalID string, decidedBy string) error {
	path := fmt.Sprintf("/mcp/approvals/%s/approve", approvalID)
	body := map[string]string{"decided_by": decidedBy}
	return a.client.doRequest(ctx, http.MethodPost, path, body, nil)
}

// Deny denies a pending elevation request.
func (a *ApprovalsAPI) Deny(ctx context.Context, approvalID string, decidedBy string) error {
	path := fmt.Sprintf("/mcp/approvals/%s/deny", approvalID)
	body := map[string]string{"decided_by": decidedBy}
	return a.client.doRequest(ctx, http.MethodPost, path, body, nil)
}

// Get retrieves an approval request by ID.
func (a *ApprovalsAPI) Get(ctx context.Context, approvalID string) (*ApprovalRequestStatus, error) {
	var approval ApprovalRequestStatus
	path := fmt.Sprintf("/mcp/approvals/%s", approvalID)
	if err := a.client.doRequest(ctx, http.MethodGet, path, nil, &approval); err != nil {
		return nil, err
	}
	return &approval, nil
}
