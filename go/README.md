# AgentTrust ID Go SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/agenttrustid/sdk/go.svg)](https://pkg.go.dev/github.com/agenttrustid/sdk/go)
[![Go Version](https://img.shields.io/github/go-mod/go-version/agenttrustid/sdk?filename=go%2Fgo.mod&cacheSeconds=300)](go.mod)

Go client library for [AgentTrust ID](https://github.com/agenttrustid/sdk) -- secure identity, authorization, and audit for AI agents.

## Install

```bash
go get github.com/agenttrustid/sdk/go
```

**Zero external dependencies** -- uses only the Go standard library.

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/agenttrustid/sdk/go"
)

func main() {
    ctx := context.Background()

    // Create a client
    client := agenttrust.NewClient(
        agenttrust.WithBaseURL("http://localhost:8080"),
        agenttrust.WithAPIKey("sk_live_your_key"),
    )

    // Register an agent
    agent, err := client.Agents.Create(ctx, agenttrust.CreateAgentRequest{
        Name:         "my-assistant",
        Framework:    "langchain",
        Capabilities: []string{"files:read", "web:fetch"},
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Agent created: %s\n", agent.ID)

    // Issue a short-lived opaque token (prefix "at_").
    // Tokens are NOT JWTs - they are random opaque strings. They have no
    // signature and cannot be validated client-side. To check a token,
    // call client.Tokens.Introspect, which sends it to
    // POST /api/v1/agent-tokens/introspect.
    token, err := client.Tokens.Issue(ctx, agenttrust.IssueTokenRequest{
        AgentID:  agent.ID,
        Scope:    []string{"files:read"},
        Audience: []string{"mcp://filesystem"},
        TTL:      300,
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Token issued: %s\n", token.Token) // e.g. "at_xK3z9..."

    // Server-side validation (e.g. for tool providers receiving a token):
    intro, err := client.Tokens.Introspect(ctx, agenttrust.IntrospectTokenRequest{
        Token:  token.Token,
        Target: "mcp://filesystem",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Token active: %v, agent=%s, org=%s\n",
        intro.Active, intro.AgentID, intro.OrgID)

    // Pre-flight action check
    result, err := client.Actions.Check(ctx, agenttrust.ActionCheckRequest{
        AgentID:          agent.ID,
        ToolName:         "read_file",
        ToolInputSummary: "/tmp/data.csv",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Action allowed: %v\n", result.Allowed)
}
```

## Guard Usage

The `Guard` provides a high-level wrapper that combines pre-flight checks with telemetry reporting. It is designed for agents using raw LLM SDKs (not framework-specific callbacks).

```go
ctx := context.Background()

client := agenttrust.NewClient(
    agenttrust.WithBaseURL("http://localhost:8080"),
    agenttrust.WithAPIKey("sk_live_your_key"),
)

guard := agenttrust.NewGuard(client, "agent-123",
    agenttrust.WithBlockOnDeny(true),  // return error on denied actions (default)
    agenttrust.WithFailOpen(false),    // return error if Guardian unreachable (default)
    agenttrust.WithSessionID("sess-abc"),
)
defer guard.Close(ctx)

// Before each tool call
if err := guard.Check(ctx, "web_search", "latest AI papers"); err != nil {
    log.Printf("tool denied: %v", err)
    return
}

// Execute the tool call...
start := time.Now()
result, err := doWebSearch("latest AI papers")
duration := time.Since(start).Milliseconds()

// After each tool call -- telemetry is buffered and auto-flushed at 10 events
guard.Report("web_search", err == nil, int(duration))
```

## Environment Variables

Create a client from environment variables:

```go
client := agenttrust.FromEnv()
```

| Variable      | Description                    | Default                  |
|---------------|--------------------------------|--------------------------|
| `AGENTTRUST_URL`     | Gateway URL                    | `http://localhost:8080`  |
| `AGENTTRUST_BASE_URL`| Fallback for `AGENTTRUST_URL`         | `http://localhost:8080`  |
| `AGENTTRUST_API_KEY` | Organization API key           | (none)                   |

## Error Handling

The SDK returns typed errors based on HTTP status codes:

```go
agent, err := client.Agents.Get(ctx, "nonexistent")
if err != nil {
    switch err.(type) {
    case *agenttrust.AuthenticationError:
        // 401 -- invalid or missing API key
        log.Fatal("check your API key")
    case *agenttrust.AuthorizationError:
        // 403 -- insufficient permissions
        log.Fatal("access denied")
    case *agenttrust.NotFoundError:
        // 404 -- resource does not exist
        log.Printf("agent not found")
    case *agenttrust.ValidationError:
        // 400 -- request validation failed
        log.Printf("bad request: %v", err)
    case *agenttrust.NetworkError:
        // connection refused, timeout, DNS failure
        log.Printf("network error: %v", err)
    case *agenttrust.AgentTrustError:
        // other API errors
        log.Printf("API error: %v", err)
    }
}
```

## API Reference

### Client

- `NewClient(opts ...Option) *Client` -- create with functional options
- `FromEnv() *Client` -- create from environment variables
- `client.Health(ctx) (*HealthResponse, error)` -- health check

#### Client Options

- `WithBaseURL(url string) Option` -- set the AgentTrust gateway base URL (default: `"http://localhost:8080"`)
- `WithAPIKey(key string) Option` -- set the organization API key (sent as `X-API-Key` header)
- `WithTimeout(d time.Duration) Option` -- set the HTTP request timeout (default: 30s)
- `WithHTTPClient(hc *http.Client) Option` -- set a custom `*http.Client` (overrides timeout)

### Agents

- `client.Agents.Create(ctx, req) (*Agent, error)` -- register a new agent
- `client.Agents.Get(ctx, agentID) (*Agent, error)` -- get agent by ID
- `client.Agents.List(ctx, orgID) ([]*Agent, error)` -- list agents; pass `""` for orgID to list all agents
- `client.Agents.Revoke(ctx, agentID, reason) error` -- permanently revoke

### Tokens

- `client.Tokens.Issue(ctx, req) (*Token, error)` -- issue capability token
- `client.Tokens.Introspect(ctx, req) (*IntrospectionResult, error)` -- POST /api/v1/agent-tokens/introspect
- `client.Tokens.Revoke(ctx, token, reason) error` -- revoke token

### Actions

- `client.Actions.Check(ctx, req) (*ActionCheckResult, error)` -- pre-flight check

### Sessions

- `client.Sessions.InitSession(ctx, req) (*Session, error)` -- create an MCP-backed AgentTrust session
- `client.Sessions.GetSession(ctx, sessionID) (*Session, error)` -- fetch session state
- `client.Sessions.InitAPISession(ctx, req) (*Session, error)` -- bridge an AgentTrust API token into a local AgentTrust session

### Approvals

- `client.Approvals.Approve(ctx, approvalID, decidedBy) error` -- approve a pending elevation
- `client.Approvals.Deny(ctx, approvalID, decidedBy) error` -- deny a pending elevation
- `client.Approvals.Get(ctx, approvalID) (*ApprovalRequestStatus, error)` -- fetch approval status

### Delegations

- `client.Delegations.Create(ctx, req) (*Delegation, error)` -- create a delegation
- `client.Delegations.List(ctx) ([]Delegation, error)` -- list current delegations
- `client.Delegations.Revoke(ctx, delegationID) error` -- revoke a delegation
- `client.Delegations.InitSession(ctx, delegationID) (*Session, error)` -- create a session from a delegation

### Federation

- `client.Federation.RegisterProvider(ctx, req) (*FederationProvider, error)` -- register an OIDC provider
- `client.Federation.ListProviders(ctx) ([]FederationProvider, error)` -- list registered providers
- `client.Federation.DeleteProvider(ctx, providerID) error` -- delete a provider
- `client.Federation.VerifyToken(ctx, req) (*VerifyFederatedTokenResponse, error)` -- verify a federated ID token
- `client.Federation.InitSession(ctx, req) (*Session, error)` -- bridge a federated token into AgentTrust
- `client.Federation.IssueIDToken(ctx, agentID, req) (*IssueIDTokenResponse, error)` -- issue an ID token for federation

### SIEM Streaming

- `client.Streaming.Create(ctx, req) (*SIEMDestination, error)` -- create a SIEM destination
- `client.Streaming.List(ctx) ([]SIEMDestination, error)` -- list destinations
- `client.Streaming.Get(ctx, id) (*SIEMDestination, error)` -- fetch a destination
- `client.Streaming.Update(ctx, id, req) (*SIEMDestination, error)` -- update a destination
- `client.Streaming.Delete(ctx, id) error` -- delete a destination
- `client.Streaming.DeliveryLog(ctx, id) ([]SIEMDeliveryRecord, error)` -- fetch delivery history
- `client.Streaming.Test(ctx, id) error` -- send a test event

### Telemetry

- `client.Telemetry.Report(ctx, agentID, sessionID, events) error` -- report events

### Guard

- `NewGuard(client, agentID, opts...) *Guard` -- create guard
- `guard.Check(ctx, toolName, inputSummary) error` -- pre-flight check
- `guard.Report(toolName, success, durationMs)` -- record telemetry (buffered)
- `guard.Flush(ctx) error` -- send buffered events
- `guard.Close(ctx) error` -- flush and clean up

#### Guard Options

- `WithBlockOnDeny(block bool) GuardOption` -- control whether `Check` returns an error when an action is denied (default: `true`)
- `WithFailOpen(open bool) GuardOption` -- control behavior when the Guardian service is unreachable; if `true`, actions are allowed when the service is down (default: `false`)
- `WithSessionID(id string) GuardOption` -- set a custom session ID (default: auto-generated UUID v4)

### Error Types

All errors implement the `error` interface. The base type is `AgentTrustError`:

```go
type AgentTrustError struct {
    Message string // human-readable error description
    Code    string // machine-readable error code (e.g., "AUTH_FAILED", "NETWORK_ERROR")
    Status  int    // HTTP status code from the API response, or 0 if not applicable
}
```

Specialized error types embed `AgentTrustError`:

| Type | HTTP Status | Code |
|------|-------------|------|
| `*AuthenticationError` | 401 | `AUTH_FAILED` |
| `*AuthorizationError` | 403 | `AUTH_DENIED` |
| `*ValidationError` | 400 | `VALIDATION_ERROR` |
| `*NotFoundError` | 404 | `NOT_FOUND` |
| `*NetworkError` | -- | `NETWORK_ERROR` |

### Exported Types

All request and response types are exported from the `agenttrust` package: `CreateAgentRequest`, `IssueTokenRequest`, `IntrospectTokenRequest`, `ActionCheckRequest`, `Agent`, `Token`, `IntrospectionResult`, `ActionCheckResult`, `TelemetryEvent`, `HealthResponse`, and more. See the [GoDoc](https://pkg.go.dev/github.com/agenttrustid/sdk/go) for the full list and field-level documentation.

## License

Apache License 2.0 - see [LICENSE](./LICENSE) in this directory.
