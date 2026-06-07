# AgentTrust ID Java SDK

[![Maven Central](https://img.shields.io/maven-central/v/id.agenttrust/agenttrustid?cacheSeconds=300)](https://central.sonatype.com/artifact/id.agenttrust/agenttrustid)

Java SDK for **AgentTrust ID**: secure, auditable AI agent operations.

Requires **Java 21+**. Zero runtime dependencies (JDK only).

## Installation

### Maven

```xml
<dependency>
    <groupId>id.agenttrust</groupId>
    <artifactId>agenttrustid</artifactId>
    <version>0.3.0</version>
</dependency>
```

### Gradle

```groovy
implementation 'id.agenttrust:agenttrustid:0.3.0'
```

## Quick Start

```java
import id.agenttrust.sdk.*;
import id.agenttrust.sdk.models.*;

import java.util.List;

public class QuickStart {
    public static void main(String[] args) throws Exception {
        // Create client
        AgentTrustClient client = AgentTrustClient.builder()
                .baseUrl("http://localhost:8080")
                .apiKey("sk_live_xxx")
                .build();

        // Check health
        HealthResponse health = client.health();
        System.out.println("Status: " + health.getStatus());

        // Register an agent
        Agent agent = client.agents().create(
                CreateAgentRequest.builder()
                        .name("my-java-agent")
                        .framework("custom")
                        .capabilities(List.of("files:read", "web:fetch"))
                        .build()
        );
        System.out.println("Agent ID: " + agent.getId());

        // Issue a short-lived opaque token (prefix "at_").
        // Tokens are NOT JWTs - they are random opaque strings. They have
        // no signature and cannot be validated client-side. To check a
        // token, call client.tokens().introspect(...) which sends it to
        // POST /api/v1/agent-tokens/introspect.
        Token token = client.tokens().issue(
                TokensAPI.IssueTokenRequest.builder()
                        .agentId(agent.getId())
                        .scope(List.of("files:read"))
                        .audience(List.of("mcp://filesystem"))
                        .ttl(300)
                        .build()
        );
        System.out.println("Token: " + token.getToken()); // e.g. "at_xK3z9..."

        // Server-side validation (for tool providers receiving a token):
        IntrospectionResult result = client.tokens().introspect(
                TokensAPI.IntrospectTokenRequest.builder()
                        .token(token.getToken())
                        .target("mcp://filesystem")
                        .requiredScopes(List.of("files:read"))
                        .build()
        );
        System.out.println("Active: " + result.isActive());

        // Pre-flight action check
        ActionCheckResult check = client.actions().check(
                ActionsAPI.ActionCheckRequest.builder()
                        .agentId(agent.getId())
                        .toolName("web_search")
                        .toolInputSummary("AI news")
                        .build()
        );
        System.out.println("Allowed: " + check.isAllowed());

        client.close();
    }
}
```

## Guard Usage

`AgentTrustGuard` provides a high-level wrapper that combines pre-flight action checks
with buffered telemetry reporting. It is thread-safe and auto-flushes after 10
events.

```java
try (AgentTrustClient client = AgentTrustClient.fromEnv();
     AgentTrustGuard guard = new AgentTrustGuard(client, agent.getId())) {

    // Before each tool call
    guard.check("web_search", "AI news bay area");

    // Execute the tool call...
    long start = System.currentTimeMillis();
    // ... do work ...
    int durationMs = (int) (System.currentTimeMillis() - start);

    // After each tool call
    guard.report("web_search", true, durationMs);
}
// guard.close() is called automatically, flushing remaining telemetry
```

### Guard Options

```java
AgentTrustGuard.Options opts = new AgentTrustGuard.Options();
opts.blockOnDeny = true;   // throw AgentTrustException on denied actions (default: true)
opts.failOpen = false;     // allow when Guardian is unreachable (default: false)
opts.sessionId = "sess-1"; // custom session ID (default: auto-generated UUID)

AgentTrustGuard guard = new AgentTrustGuard(client, agentId, opts);
```

## API Surface

The Java SDK mirrors the TypeScript and Go SDKs. All APIs are typed and accessible
via the main `AgentTrustClient`:

| API                    | Accessor                | Purpose                                              |
|------------------------|-------------------------|------------------------------------------------------|
| `AgentsAPI`            | `client.agents()`       | Agent registration and lifecycle                     |
| `TokensAPI`            | `client.tokens()`       | Opaque agent token issue/introspect/revoke           |
| `ActionsAPI`           | `client.actions()`      | Pre-flight Fast Guard authorization checks           |
| `TelemetryAPI`         | `client.telemetry()`    | Audit-trail telemetry reporting                      |
| `SessionsAPI`          | `client.sessions()`     | MCP session initialization                           |
| `ApprovalsAPI`         | `client.approvals()`    | Elevation approval workflow                          |
| `AgentCardsAPI`        | `client.agentCards()`   | A2A agent card generate / get / publish              |
| `A2AAPI`               | `client.a2a()`          | Agent-to-Agent JSON-RPC task dispatch                |
| `MCPAPI`               | `client.mcp()`          | MCP server registration and proxy tool calls         |
| `DelegationsAPI`       | `client.delegations()`  | Capability delegation chains                         |
| `FederationAPI`        | `client.federation()`   | OIDC provider registration, federated tokens         |
| `StreamingAPI`         | `client.streaming()`    | SIEM destination management and delivery logs       |
| `WIMSEAPI`             | `client.wimse()`        | WIMSE workload identity tokens                       |

### A2A example

```java
A2ATask task = client.a2a().sendTask(
        "agent-1",
        "agent-2",
        Map.of("text", "summarize today's news")
);
A2ATask updated = client.a2a().getTask(task.getId());
```

### Delegations example

```java
Delegation d = client.delegations().create(
        DelegationsAPI.CreateDelegationRequest.builder()
                .fromAgentId("agent-1")
                .toAgentId("agent-2")
                .scope(List.of("files:read"))
                .ttlSeconds(3600)
                .build());

Session session = client.delegations().initSession(d.getId());
```

### Federation example

```java
FederationProvider provider = client.federation().registerProvider(
        "https://idp.example.com", "ACME IdP", "high");

FederationAPI.VerifyTokenResult v = client.federation().verifyToken(
        externalIDToken, "https://idp.example.com");

if (v.isValid()) {
    Session s = client.federation().initSession(externalIDToken, null);
}
```

### WIMSE example

```java
WIMSEAPI.WIMSETokenResponse wimse = client.wimse().issueToken(
        WIMSEAPI.IssueWIMSETokenRequest.builder()
                .agentId("agent-1")
                .serviceName("payments")
                .environment("prod")
                .ttlSeconds(3600)
                .build());

WIMSEAPI.VerifyWIMSETokenResponse verified =
        client.wimse().verifyToken(wimse.getToken(), "acme.com");
```

## Environment Variables

| Variable       | Description                        | Default                  |
|----------------|------------------------------------|--------------------------|
| `AGENTTRUST_URL`      | Gateway URL                                  | `http://localhost:8080`  |
| `AGENTTRUST_BASE_URL` | Fallback for `AGENTTRUST_URL`                | `http://localhost:8080`  |
| `AGENTTRUST_API_KEY`  | Organization API key (sk_live_xxx)           | (none)                   |

```java
AgentTrustClient client = AgentTrustClient.fromEnv();
```

## Error Handling

All SDK methods throw checked exceptions extending `AgentTrustException`:

| Exception                 | HTTP Status | Description                    |
|---------------------------|-------------|--------------------------------|
| `AuthenticationException` | 401         | Invalid or missing API key     |
| `AuthorizationException`  | 403         | Insufficient permissions       |
| `ValidationException`     | 400         | Invalid request parameters     |
| `NotFoundException`       | 404         | Resource not found             |
| `NetworkException`        | --          | Connection/timeout failure     |

```java
try {
    client.agents().get("nonexistent");
} catch (NotFoundException e) {
    System.err.println("Agent not found: " + e.getMessage());
} catch (AuthenticationException e) {
    System.err.println("Bad credentials: " + e.getMessage());
} catch (AgentTrustException e) {
    System.err.println("AgentTrust error [" + e.getCode() + "]: " + e.getMessage());
}
```

## Requirements

- Java 21+
- No runtime dependencies (uses `java.net.http.HttpClient`)

## Building

```bash
mvn clean compile
mvn test
```

## License

Apache License 2.0 - see [LICENSE](./LICENSE) in this directory.
