package agenttrust

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

const (
	// guardAutoFlushSize is the number of buffered events that triggers an auto-flush.
	guardAutoFlushSize = 10
)

// Guard provides a high-level wrapper for pre-flight action checks and
// telemetry reporting. It is designed for agents using raw OpenAI/Anthropic
// SDKs (not framework-specific callbacks).
//
// Guard is safe for concurrent use. Telemetry events are buffered and
// automatically flushed when the buffer reaches 10 events.
//
// Example:
//
//	guard := ati.NewGuard(client, "agent-123",
//	    ati.WithBlockOnDeny(true),
//	    ati.WithFailOpen(false),
//	)
//	defer guard.Close(ctx)
//
//	// Before each tool call
//	if err := guard.Check(ctx, "web_search", "AI news"); err != nil {
//	    log.Printf("tool denied: %v", err)
//	    return
//	}
//
//	// Execute the tool call...
//
//	// After each tool call
//	guard.Report("web_search", true, 1200)
type Guard struct {
	client              *Client
	agentID             string
	sessionID           string
	blockOnDeny         bool
	failOpen            bool
	defaultActionEffect string

	mu     sync.Mutex
	buffer []TelemetryEvent
}

// GuardOption configures a Guard. Use the With* guard option functions to create options.
type GuardOption func(*Guard)

// WithSessionID sets a custom session ID for the guard.
// If not set, a random UUID is generated.
func WithSessionID(id string) GuardOption {
	return func(g *Guard) {
		g.sessionID = id
	}
}

// WithBlockOnDeny controls whether Check returns an error when an action is denied.
// Default: true (denied actions return an error).
func WithBlockOnDeny(block bool) GuardOption {
	return func(g *Guard) {
		g.blockOnDeny = block
	}
}

// WithFailOpen controls behavior when the Guardian service is unreachable.
// If true, actions are allowed when the service is down. If false (default),
// an error is returned.
func WithFailOpen(open bool) GuardOption {
	return func(g *Guard) {
		g.failOpen = open
	}
}

// WithActionEffect sets a default action effect hint for all checks.
// Valid values: "read", "mutating", "destructive", "admin".
// If empty (default), the backend auto-classifies each action.
func WithActionEffect(effect string) GuardOption {
	return func(g *Guard) {
		g.defaultActionEffect = effect
	}
}

// NewGuard creates a new Guard for the given agent.
//
// By default:
//   - blockOnDeny is true (denied actions return errors)
//   - failOpen is false (errors on Guardian unavailability)
//   - sessionID is auto-generated as a UUID v4
func NewGuard(client *Client, agentID string, opts ...GuardOption) *Guard {
	g := &Guard{
		client:      client,
		agentID:     agentID,
		sessionID:   generateUUID(),
		blockOnDeny: true,
		failOpen:    false,
		buffer:      make([]TelemetryEvent, 0, guardAutoFlushSize),
	}

	for _, opt := range opts {
		opt(g)
	}

	return g
}

// Check performs a pre-flight authorization check for a tool call.
//
// If the action is allowed, nil is returned.
//
// If the action is denied and blockOnDeny is true, an *AgentTrustError with code
// "ACTION_DENIED" is returned. If blockOnDeny is false, nil is returned
// (the denial is silent).
//
// If the Guardian service is unreachable and failOpen is true, nil is returned
// (fail-open behavior). If failOpen is false, a *NetworkError is returned.
func (g *Guard) Check(ctx context.Context, toolName string, inputSummary string) error {
	req := ActionCheckRequest{
		AgentID:          g.agentID,
		Action:           "tool_call",
		ToolName:         toolName,
		ToolInputSummary: inputSummary,
		SessionID:        g.sessionID,
		ActionEffect:     g.defaultActionEffect,
	}

	result, err := g.client.Actions.Check(ctx, req)
	if err != nil {
		// Network errors respect failOpen setting
		if _, ok := err.(*NetworkError); ok {
			if g.failOpen {
				return nil
			}
			return &AgentTrustError{
				Message: fmt.Sprintf("Guardian unreachable: %v", err),
				Code:    "GUARDIAN_UNAVAILABLE",
			}
		}
		// Non-network errors are always returned
		return err
	}

	if !result.Allowed {
		if g.blockOnDeny {
			if result.ElevationRequired {
				return &ElevationRequiredError{
					AgentTrustError: AgentTrustError{
						Message: fmt.Sprintf("Tool '%s' requires elevation: %s", toolName, result.Reason),
						Code:    "ELEVATION_REQUIRED",
					},
					ApprovalID: result.ApprovalID,
				}
			}
			return &AgentTrustError{
				Message: fmt.Sprintf("Tool '%s' denied: %s", toolName, result.Reason),
				Code:    "ACTION_DENIED",
			}
		}
		// blockOnDeny is false: silently allow
	}

	return nil
}

// Report records a tool call result as a telemetry event.
//
// Events are buffered in memory and automatically flushed when the buffer
// reaches 10 events. Call Flush or Close to send remaining events.
//
// This method never returns an error; telemetry is best-effort.
func (g *Guard) Report(toolName string, success bool, durationMs int) {
	eventType := "tool_end"
	if !success {
		eventType = "tool_error"
	}

	event := TelemetryEvent{
		EventType:  eventType,
		ToolName:   toolName,
		DurationMs: durationMs,
		Success:    success,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}

	g.mu.Lock()
	g.buffer = append(g.buffer, event)
	shouldFlush := len(g.buffer) >= guardAutoFlushSize
	g.mu.Unlock()

	if shouldFlush {
		// Best-effort flush; errors are silently ignored.
		_ = g.Flush(context.Background())
	}
}

// Flush sends all buffered telemetry events to the AgentTrust ID audit service.
//
// This method is safe to call concurrently. If the buffer is empty, it
// returns nil immediately. Flush errors are returned but should generally
// be handled as non-fatal.
func (g *Guard) Flush(ctx context.Context) error {
	g.mu.Lock()
	if len(g.buffer) == 0 {
		g.mu.Unlock()
		return nil
	}
	events := make([]TelemetryEvent, len(g.buffer))
	copy(events, g.buffer)
	g.buffer = g.buffer[:0]
	g.mu.Unlock()

	return g.client.Telemetry.Report(ctx, g.agentID, g.sessionID, events)
}

// Close flushes any remaining telemetry events and releases resources.
//
// Always call Close (or defer guard.Close(ctx)) when the guard is no longer needed.
func (g *Guard) Close(ctx context.Context) error {
	return g.Flush(ctx)
}

// generateUUID generates a random UUID v4 string using crypto/rand.
func generateUUID() string {
	var uuid [16]byte
	_, _ = rand.Read(uuid[:])
	// Set version (4) and variant (RFC 4122)
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}
