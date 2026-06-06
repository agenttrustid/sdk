package agenttrust

import (
	"context"
	"net/http"
)

// TelemetryAPI provides agent behavior telemetry reporting.
//
// Telemetry events are used to build an audit trail of agent behavior,
// including tool calls, durations, and error rates.
type TelemetryAPI struct {
	client *Client
}

// Report sends a batch of telemetry events to the AgentTrust ID audit service.
//
// Events should include tool call start/end timestamps, durations, success
// status, and any error types. This data is used for audit trails and
// behavioral anomaly detection.
//
// Example:
//
//	err := client.Telemetry.Report(ctx, "agent-123", "session-456", []ati.TelemetryEvent{
//	    {
//	        EventType:  "tool_end",
//	        ToolName:   "web_search",
//	        DurationMs: 1200,
//	        Success:    true,
//	        Timestamp:  time.Now().UTC().Format(time.RFC3339),
//	    },
//	})
func (t *TelemetryAPI) Report(ctx context.Context, agentID string, sessionID string, events []TelemetryEvent) error {
	req := TelemetryReportRequest{
		AgentID:   agentID,
		SessionID: sessionID,
		Events:    events,
	}
	return t.client.doRequest(ctx, http.MethodPost, "/api/v1/telemetry/report", req, nil)
}
