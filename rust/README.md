# AgentTrust Rust SDK

Rust SDK for **AgentTrust** -- authentication and authorization for AI agents.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
agenttrustid = "0.3"
```

## Quick Start

```rust
use agenttrustid::{AgentTrustClient, CreateAgentRequest, IntrospectTokenRequest, IssueTokenRequest};

fn main() -> agenttrustid::Result<()> {
    // Create a client
    let client = AgentTrustClient::builder()
        .base_url("http://localhost:8080")
        .api_key("sk_live_xxx")
        .build()?;

    // Register an agent
    let agent = client.agents().create(&CreateAgentRequest {
        name: "my-assistant".to_string(),
        framework: "langchain".to_string(),
        capabilities: vec!["files:read".to_string(), "web:fetch".to_string()],
        ..Default::default()
    })?;
    println!("Agent ID: {}", agent.id);

    // Issue a short-lived opaque token (prefix `at_`).
    //
    // Tokens are NOT JWTs - they are random opaque strings. They have no
    // signature and cannot be validated client-side. To check a token, call
    // `client.tokens().introspect(...)` which sends it to
    // POST /api/v1/agent-tokens/introspect.
    let token = client.tokens().issue(&IssueTokenRequest {
        agent_id: agent.id.clone(),
        scope: vec!["files:read".to_string()],
        audience: vec!["mcp://filesystem".to_string()],
        ttl: 300,
    })?;
    println!("Bearer {}", token.token); // e.g. "at_xK3z9..."

    // Server-side validation (for tool providers receiving a token):
    let result = client.tokens().introspect(&IntrospectTokenRequest {
        token: token.token.clone(),
        target: Some("mcp://filesystem".to_string()),
        required_scopes: vec!["files:read".to_string()],
    })?;

    if result.active {
        println!("Access granted");
    }

    Ok(())
}
```

## Guard Pattern

For agents using raw OpenAI/Anthropic SDKs, the `AgentTrustGuard` provides a simple check-then-report pattern with automatic telemetry buffering and flush-on-drop:

```rust
use agenttrustid::{AgentTrustClient, AgentTrustGuard};

fn main() -> agenttrustid::Result<()> {
    let client = AgentTrustClient::from_env()?;

    // Guard owns the client and manages a session
    let guard = AgentTrustGuard::builder(client, "agent-123")
        .block_on_deny(true)
        .fail_open(false)
        .build();

    // Before each tool call
    guard.check("web_search", "AI news")?;

    // Execute tool call...

    // After each tool call
    guard.report("web_search", true, 1200);

    // Telemetry is automatically flushed when guard is dropped,
    // or when the buffer reaches 10 events.
    // You can also flush manually:
    guard.flush()?;

    Ok(())
}
```

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `AGENTTRUST_URL` | Gateway base URL | `http://localhost:8080` |
| `AGENTTRUST_BASE_URL` | Fallback for `AGENTTRUST_URL` | `http://localhost:8080` |
| `AGENTTRUST_API_KEY` | Organization API key | (none) |

```rust
let client = AgentTrustClient::from_env()?;
```

## Error Handling

All fallible operations return `Result<T, AgentTrustError>`. Use pattern matching for specific error handling:

```rust
use agenttrustid::{AgentTrustClient, AgentTrustError};

let client = AgentTrustClient::builder().build().unwrap();

match client.agents().get("agent-123") {
    Ok(agent) => println!("Found: {}", agent.name),
    Err(AgentTrustError::NotFound { .. }) => println!("Agent does not exist"),
    Err(AgentTrustError::Authentication { .. }) => println!("Invalid API key"),
    Err(AgentTrustError::Authorization { .. }) => println!("Insufficient permissions"),
    Err(AgentTrustError::Validation { message, .. }) => println!("Bad request: {}", message),
    Err(AgentTrustError::Network(e)) => println!("Network error: {}", e),
    Err(AgentTrustError::ActionDenied { message, check_id }) => {
        println!("Action denied: {} (check: {:?})", message, check_id)
    }
    Err(AgentTrustError::GuardianUnavailable { message }) => {
        println!("Guardian unreachable: {}", message)
    }
    Err(AgentTrustError::Api { message, code, status }) => {
        println!("API error {}: {} ({})", status, message, code)
    }
    Err(AgentTrustError::Json(e)) => println!("JSON error: {}", e),
    Err(e) => println!("Other error: {}", e),
}
```

### AgentTrustError Variants

| Variant | Description |
|---|---|
| `Authentication { message, status }` | HTTP 401 -- invalid or missing API key |
| `Authorization { message, status }` | HTTP 403 -- insufficient permissions |
| `Validation { message, status }` | HTTP 400 -- request validation failed |
| `NotFound { message, status }` | HTTP 404 -- resource does not exist |
| `Network(reqwest::Error)` | Connection refused, timeout, DNS failure |
| `ActionDenied { message, check_id }` | Guard check returned "denied" (`check_id` is `Option<String>`) |
| `GuardianUnavailable { message }` | Guardian service unreachable and `fail_open` is `false` |
| `Api { message, code, status }` | Generic API error for other HTTP status codes |
| `Json(serde_json::Error)` | JSON serialization or deserialization failed |

The `ActionDenied` and `GuardianUnavailable` variants are especially relevant when using `AgentTrustGuard`.

## Features

| Feature | Description | Default |
|---|---|---|
| `blocking` | Synchronous (blocking) HTTP client | Yes |
| `async` | Async support via `tokio` | No |

The SDK uses blocking HTTP by default, which is simpler for most agent use cases. Enable the `async` feature for non-blocking I/O:

```toml
[dependencies]
agenttrustid = { version = "0.3", default-features = false, features = ["async"] }
```

## API Reference

### AgentTrustClient

- `AgentTrustClient::builder()` -- Configure with builder pattern
- `AgentTrustClient::from_env()` -- Configure from environment variables
- `client.health()` -- Health check
- `client.agents()` -- Agent management
- `client.tokens()` -- Token operations
- `client.actions()` -- Action authorization
- `client.telemetry()` -- Telemetry reporting
- `client.sessions()` -- AgentTrust session management
- `client.approvals()` -- Elevation approval workflow
- `client.agentcards()` -- A2A agent card publishing
- `client.a2a()` -- Agent-to-agent task dispatch
- `client.mcp()` -- MCP server registry and proxy
- `client.delegations()` -- Capability delegation chains
- `client.federation()` -- Cross-org OIDC federation
- `client.streaming()` -- SIEM streaming destinations
- `client.wimse()` -- WIMSE workload identity tokens

### AgentsAPI

- `create(req)` -- Register a new agent (returns private key)
- `get(id)` -- Get agent by ID
- `list(org_id: Option<&str>)` -- List agents; pass `None` to list all agents
- `revoke(id, reason)` -- Permanently revoke an agent

### TokensAPI

- `issue(req)` -- Issue an opaque agent token
- `introspect(req)` -- Introspect a token server-side
- `revoke(token, reason)` -- Revoke a token

### ActionsAPI

- `check(req)` -- Pre-flight action authorization check

### TelemetryAPI

- `report(agent_id, session_id, events)` -- Report telemetry events

### SessionsAPI

- `init_session(agent_id, server_id)` -- Initialize an MCP session
- `get_session(session_id)` -- Retrieve a session

### ApprovalsAPI

- `approve(approval_id, decided_by)` -- Approve an elevation
- `deny(approval_id, decided_by)` -- Deny an elevation
- `get(approval_id)` -- Get approval status

### AgentCards

- `generate(agent_id)` -- Generate a card
- `get(agent_id)` -- Fetch the current card
- `publish(agent_id)` -- Publish (make publicly discoverable)
- `get_public(agent_id)` -- Fetch a public agent card

### A2A

- `send_message(agent_id, text, message_id, task_id)` -- Send an A2A v1.0 `message/send` to an agent
- `create_task(req)` -- Send a task to a target agent (`tasks/send`)
- `get_task(id)` -- Get task status
- `cancel_task(id)` -- Cancel a running task
- `list_tasks()` -- List recent tasks

### Mcp

- `list_servers()` -- List registered MCP servers
- `get_server(id)` -- Get MCP server by ID
- `register_server(req)` -- Register a new MCP server
- `remove_server(id)` -- Remove an MCP server
- `call_tool(server_id, method, params)` -- JSON-RPC proxy call

### Delegations

- `create(req)` -- Create a delegation
- `get(id)` -- Get delegation by ID
- `list()` -- List delegations
- `revoke(id)` -- Revoke a delegation
- `init_session(id)` -- Bridge a delegation into a session

### Federation

- `register_provider(req)` -- Register an OIDC provider
- `list_providers()` -- List providers
- `delete_provider(id)` -- Remove a provider
- `issue_token(agent_id, req)` -- Issue a federated ID token
- `introspect_token(req)` -- Verify a federated token
- `revoke_token(token)` -- Revoke a federated token
- `init_session(req)` -- Bridge a federated token into a session

### Streaming

- `create(req)` -- Create a SIEM destination
- `list()` -- List SIEM destinations
- `get(id)` -- Get a SIEM destination
- `update(id, req)` -- Update a SIEM destination
- `delete(id)` -- Delete a SIEM destination
- `delivery_log(id)` -- Recent delivery records
- `test(id)` -- Send a test event
- `subscribe(filter, handler)` -- Polling subscription stub for delivery log

### Wimse

- `issue_token(req)` -- Issue a WIMSE workload identity token
- `verify_wimse(req)` -- Verify a WIMSE token
- `get_jwt_signed_headers(req)` -- Build the headers to attach downstream

### AgentTrustGuard

- `AgentTrustGuard::new(client, agent_id)` -- Create with defaults
- `AgentTrustGuard::builder(client, agent_id)` -- Configure with builder
- `guard.check(tool, input)` -- Pre-flight check
- `guard.report(tool, success, ms)` -- Record tool result
- `guard.flush()` -- Send buffered events
- Auto-flushes at 10 events and on `Drop`

## License

Apache License 2.0 - see [LICENSE](./LICENSE) in this directory.
