package agenttrust

import (
	"context"
	"net/http"
	"testing"
)

func TestMCPCallToolSendsAgentAndSessionHeaders(t *testing.T) {
	var gotAgentID, gotSessionID string
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /mcp/srv-1": func(w http.ResponseWriter, r *http.Request) {
			gotAgentID = r.Header.Get("X-Agent-ID")
			gotSessionID = r.Header.Get("X-Session-ID")
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"value":42}}`))
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	result, err := c.MCP.CallTool(context.Background(), "srv-1", "agent-1", "tools/call",
		map[string]interface{}{"name": "test"}, "sess-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAgentID != "agent-1" {
		t.Errorf("expected X-Agent-ID=agent-1, got %q", gotAgentID)
	}
	if gotSessionID != "sess-1" {
		t.Errorf("expected X-Session-ID=sess-1, got %q", gotSessionID)
	}
	if v, ok := result["value"].(float64); !ok || v != 42 {
		t.Errorf("expected result.value=42, got %v", result["value"])
	}
}

func TestMCPCallToolRequiresAgentID(t *testing.T) {
	c := NewClient(WithBaseURL("http://localhost:0"))
	_, err := c.MCP.CallTool(context.Background(), "srv-1", "", "tools/list", nil, "")
	if err == nil {
		t.Fatal("expected error when agentID is empty, got nil")
	}
}
