# AgentTrust ID Python SDK

Authentication, authorization, and runtime security for AI agents.

[![PyPI](https://img.shields.io/pypi/v/agenttrustid)](https://pypi.org/project/agenttrustid/)
[![Python](https://img.shields.io/pypi/pyversions/agenttrustid)](https://pypi.org/project/agenttrustid/)


## Install

```bash
pip install agenttrustid

# With LangChain support:
pip install agenttrustid[langchain]
```

## Quick Start

```python
from agenttrustid import AgentTrustClient

client = AgentTrustClient(base_url="http://localhost:8080", api_key="sk_live_...")

# Register an agent
agent = client.agents.create(
    name="my-agent",
    framework="langchain",
    capabilities=["files:read", "web:search"]
)

# Issue a short-lived opaque token (prefix `at_`).
# Tokens are NOT JWTs - they are random opaque strings. They have no
# signature and cannot be validated client-side. To check a token, call
# `client.tokens.introspect(token)`.
token = client.tokens.issue(
    agent_id=agent.id,
    scopes=["files:read"],
    ttl_seconds=300
)
print(token.token)  # e.g. "at_xK3z9..."

# Server-side validation (for tool providers receiving a token):
result = client.tokens.introspect(token.token, target="mcp://filesystem")
if result.active:
    # Token is valid; agent_id, org_id, scopes are populated
    pass

# Check an action before executing
result = client.actions.check(
    agent_id=agent.id,
    action="tool_call",
    tool_name="web_search",
    tool_input_summary="AI news",
    session_id="sess-123"
)
print(f"Allowed: {result.allowed}, Confidence: {result.confidence}")
```

## LangChain Integration

Add one callback to Guardian-protect every tool call:

```python
from agenttrustid import AgentTrustClient
from agenttrustid.callback import AgentTrustCallbackHandler
from langchain.agents import AgentExecutor

client = AgentTrustClient.from_env()  # reads AGENTTRUST_URL + AGENTTRUST_API_KEY
agent_info = client.agents.create(name="research-bot", framework="langchain")

guardian = AgentTrustCallbackHandler(
    client=client,
    agent_id=agent_info.id,
    block_on_deny=True,   # raise exception on denied actions
    fail_open=False,      # block if Guardian is unreachable
    log_inputs=False,     # don't send tool inputs (privacy default)
)

executor = AgentExecutor(agent=agent, tools=tools, callbacks=[guardian])
result = executor.invoke({"input": "Find AI safety papers"})
```

### How the Callback Works

```
on_tool_start  -->  POST /api/v1/actions/check (Fast Guard, <15ms)
                    If denied + block_on_deny: raises AgentTrustError (code="ACTION_DENIED")
on_tool_end    -->  Buffers telemetry event (async, batched)
on_chain_end   -->  POST /api/v1/telemetry/report (flushes buffer)
```

## AgentTrustGuard (Non-LangChain Agents)

For agents using raw Anthropic/OpenAI SDKs:

```python
from agenttrustid import AgentTrustClient
from agenttrustid.guard import AgentTrustGuard

client = AgentTrustClient.from_env()
guard = AgentTrustGuard(client, agent_id="your-agent-id")

# Before tool call -- raises AgentTrustError (code="ACTION_DENIED") if denied
guard.check("web_search", input_summary="AI news bay area")

# After tool call
guard.report("web_search", success=True, duration_ms=1200)

# When done
guard.close()
```

AgentTrustGuard can also be used as a context manager:

```python
with AgentTrustGuard(client, agent_id="agent-123") as guard:
    guard.check("web_search")
    # ... do tool call ...
    guard.report("web_search", success=True, duration_ms=500)
```

## Configuration

### Environment Variables

```bash
export AGENTTRUST_URL=http://localhost:8080
export AGENTTRUST_API_KEY=sk_live_...
```

```python
client = AgentTrustClient.from_env()
```

### AgentTrustClient Constructor

```python
client = AgentTrustClient(
    base_url="http://localhost:8080",  # Gateway URL
    auth_url=None,                     # Auth service URL (derived from base_url)
    audit_url=None,                    # Audit service URL (derived from base_url)
    api_key="sk_live_...",             # Organization API key
    timeout=30,                        # Request timeout in seconds
    verify_tls=True,                   # TLS certificate verification (disable only for local dev)
)
```

### AgentTrustCallbackHandler Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `client` | required | AgentTrustClient instance |
| `agent_id` | required | Agent UUID from registration |
| `block_on_deny` | `True` | Raise exception when Guardian denies |
| `fail_open` | `False` | Allow tool calls if Guardian is unreachable |
| `log_inputs` | `False` | Send truncated tool inputs (max 200 chars) |

## Privacy

The SDK is private by default:

| Data | Sent? | Notes |
|------|-------|-------|
| Tool name | Yes | e.g., `web_search` |
| Tool input | No | Only with `log_inputs=True`, truncated to 200 chars |
| Tool output | Never | Only success/failure boolean |
| Duration | Yes | Milliseconds |
| Error type | Yes | Exception class name only |
| LLM prompts | Never | SDK has no access |

## Error Handling

```python
from agenttrustid.exceptions import (
    AgentTrustError,              # Base error (also used for ACTION_DENIED with code="ACTION_DENIED")
    AuthenticationError,   # Invalid API key (401)
    AuthorizationError,    # Insufficient permissions (403)
    TokenExpiredError,     # Token TTL exceeded
    AgentRevokedError,     # Agent revoked
    NetworkError,          # Gateway unreachable
    ValidationError,       # Request validation failed (400)
)

try:
    result = client.actions.check(
        agent_id=agent.id,
        action="tool_call",
        tool_name="delete_all",
        tool_input_summary="delete everything",
        session_id="sess-1"
    )
except AuthorizationError:
    print("Action denied by Guardian")
except NetworkError:
    print("Gateway unreachable")
```

`ValidationError` is also exported from the top-level `agenttrustid` package.

## API Reference

### AgentTrustClient

```python
client = AgentTrustClient(base_url="...", api_key="...", verify_tls=True)
client = AgentTrustClient.from_env()           # AGENTTRUST_URL + AGENTTRUST_API_KEY
client = AgentTrustClient.from_config("path")  # JSON config file
```

### Agents

```python
agent = client.agents.create(name, framework, capabilities, metadata)
agents = client.agents.list(org_id=None)
agent = client.agents.get(agent_id)
client.agents.revoke(agent_id, reason)
```

### Tokens

```python
token = client.tokens.issue(agent_id, scopes, ttl_seconds=300, use_cache=True)
result = client.tokens.introspect(token_str, target=None, required_scopes=None)
client.tokens.revoke(token_str, reason)
client.tokens.clear_cache()
```

Token fields: `token.token`, `token.agent_id`, `token.scopes`, `token.audience`,
`token.issued_at`, `token.expires_at`, `token.token_id`, `token.is_expired`,
`token.ttl_seconds`.

### Actions

```python
result = client.actions.check(
    agent_id,
    action="tool_call",
    tool_name="",
    tool_input_summary="",
    session_id=""
)
# result.allowed, result.confidence, result.reason, result.guard_tier,
# result.check_id, result.latency_ms
```

### Telemetry

```python
client.telemetry.report(agent_id, session_id, events)
# events: list of dicts with keys: event_type, tool_name, duration_ms, success, error_type, timestamp
# Automatic via AgentTrustCallbackHandler -- buffers and flushes every 5s or 10 events
```

### Agent Cards

```python
card = client.agent_cards.generate(agent_id)
card = client.agent_cards.get(agent_id)
card = client.agent_cards.publish(agent_id)
card = client.agent_cards.get_public(agent_id)
# card.name, card.url, card.provider, card.version,
# card.capabilities, card.skills, card.security_policy
```

### A2A (Agent-to-Agent)

```python
task = client.a2a.send_task(
    source_agent_id="agent-123",
    target_agent_id="agent-456",
    message="Summarize the latest security report",
    metadata={"priority": "high"}
)
task = client.a2a.get_task(task_id)
task = client.a2a.cancel_task(task_id)
# task.id, task.source_agent_id, task.target_agent_id, task.status (default: "pending"),
# task.message, task.artifacts (List[Dict]), task.metadata, task.created_at, task.updated_at
```

### MCP (Model Context Protocol)

```python
server = client.mcp.register_server(
    name="filesystem",
    url="http://localhost:9000",
    capabilities=["files:read", "files:write"]
)
servers = client.mcp.list_servers()
client.mcp.remove_server(server_id)
result = client.mcp.call_tool(server_id, method="tools/call", params={...})
# result is a dict (JSON-RPC result)
# server.id, server.name, server.url, server.capabilities, server.org_id, server.created_at
```

### Delegations

```python
delegation = client.delegations.create(
    from_agent_id="agent-123",
    to_agent_id="agent-456",
    scope=["files:read"],
    ttl_seconds=3600,
    restrictions={"paths": ["/tmp/*"]},
    parent_delegation_id=None
)
delegations = client.delegations.list()  # no parameters
client.delegations.revoke(delegation_id)
session = client.delegations.init_session(delegation_id)
# delegation.id, delegation.from_agent_id, delegation.to_agent_id,
# delegation.scope, delegation.restrictions, delegation.delegation_chain,
# delegation.expires_at, delegation.revoked_at, delegation.created_at
```

### Sessions

```python
session = client.sessions.init_session(agent_id, server_id)
session = client.sessions.get_session(session_id)
session = client.sessions.init_api_session(token)
```

### Federation

```python
provider = client.federation.register_provider(
    issuer="https://issuer.example.com",
    name="Example Workforce",
    trust_level="high",
)
providers = client.federation.list_providers()
client.federation.delete_provider(provider.id)
result = client.federation.verify_token(token="eyJ...", issuer_hint=None)
session = client.federation.init_session(token="eyJ...", issuer_hint=None)
id_token = client.federation.issue_id_token(agent_id, audience=None, nonce=None, ttl=None)
```

### SIEM Streaming

```python
destination = client.streaming.create(
    name="Splunk HEC",
    destination_type="splunk",
    endpoint_url="https://splunk.example.com/services/collector",
    auth_token="secret",
)
destinations = client.streaming.list()
destination = client.streaming.get(destination.id)
destination = client.streaming.update(destination.id, is_active=True)
client.streaming.delete(destination.id)
logs = client.streaming.delivery_log(destination.id)
client.streaming.test(destination.id)
```

## Models

The following models are exported from the top-level `agenttrustid` package:

- `Agent` -- Registered AI agent
- `Token` -- Opaque agent token
- `VerificationResult` -- Token verification result
- `ActionCheckResult` -- Pre-flight action authorization check result
- `AgentCard` -- Agent Card (A2A protocol)
- `A2ATask` -- Agent-to-agent task
- `MCPServer` -- Registered MCP server
- `Delegation` -- Agent-to-agent capability delegation
- `FederationProvider` -- Registered OIDC federation provider
- `VerifyFederatedTokenResult` -- Federated token verification result
- `SIEMDestination` -- SIEM audit-stream destination
- `SIEMDeliveryRecord` -- SIEM delivery attempt record

Protocol API classes are also exported: `A2AAPI`, `AgentCardsAPI`, `MCPAPI`, `DelegationsAPI`, `FederationAPI`, `StreamingAPI`.

## Requirements

- Python >= 3.8
- No runtime dependencies (stdlib only)
- Optional: `langchain-core>=0.1.0` for LangChain callback

## License

Apache License 2.0 - see [LICENSE](./LICENSE) in this directory.
