# AgentTrust ID TypeScript SDK

Authentication, authorization, and runtime security for AI agents.

[![npm](https://img.shields.io/npm/v/@agenttrustid/sdk?cacheSeconds=300)](https://www.npmjs.com/package/@agenttrustid/sdk)
[![Node](https://img.shields.io/node/v/@agenttrustid/sdk?cacheSeconds=300)](https://www.npmjs.com/package/@agenttrustid/sdk)


## Install

```bash
npm install @agenttrustid/sdk
```

Zero runtime dependencies. Uses native `fetch` (Node 18+).

## Quick Start

```typescript
import { AgentTrustClient } from '@agenttrustid/sdk';

const client = new AgentTrustClient({
  baseUrl: 'http://localhost:8080',
  apiKey: 'sk_live_...',
});

// Register an agent
const agent = await client.agents.create({
  name: 'my-agent',
  framework: 'langchain',
  capabilities: ['files:read', 'web:search'],
});

// Issue a short-lived opaque token (prefix `at_`).
// Tokens are NOT JWTs - they are random opaque strings. They have no
// signature and cannot be validated client-side. To check a token, call
// `client.tokens.introspect({ token })`.
const token = await client.tokens.issue({
  agentId: agent.id,
  scopes: ['files:read'],
  ttlSeconds: 300,
});
console.log(token.token); // e.g. "at_xK3z9..."

// Server-side validation (for tool providers receiving a token):
const result = await client.tokens.introspect({
  token: token.token,
  target: 'api.example.com',
});
if (result.active) {
  // Token is valid; agentId, orgId, scopes are populated
}

// Check an action before executing
const result = await client.actions.check({
  agentId: agent.id,
  action: 'tool_call',
  toolName: 'web_search',
});
console.log(`Allowed: ${result.allowed}, Confidence: ${result.confidence}`);
```

## AgentTrustGuard

Wraps action checking with automatic deny handling and telemetry buffering:

```typescript
import { AgentTrustClient, AgentTrustGuard } from '@agenttrustid/sdk';

const client = new AgentTrustClient({ baseUrl: '...', apiKey: '...' });
const agent = await client.agents.create({ name: 'my-agent' });

const guard = new AgentTrustGuard(client, agent.id, {
  blockOnDeny: true,  // throw on denied actions (default)
  failOpen: false,    // block if Guardian unreachable (default)
});

// Check before tool execution
const allowed = await guard.check('web_search', 'query about AI safety');

// Report tool outcome (batched, async)
guard.report('web_search', true, 150); // tool, success, duration_ms

// Flush before exit
await guard.flush();
```

## Environment Variables

```bash
export AGENTTRUST_URL=http://localhost:8080
export AGENTTRUST_API_KEY=sk_live_...
```

```typescript
const client = AgentTrustClient.fromEnv();
```

## Error Handling

```typescript
import {
  AgentTrustError,              // Base error
  AuthenticationError,   // Invalid API key (401)
  AuthorizationError,    // Insufficient permissions (403)
  TokenExpiredError,     // Token has expired
  AgentRevokedError,     // Agent has been revoked
  NetworkError,          // Gateway unreachable
  ValidationError,       // Invalid request (400)
} from '@agenttrustid/sdk';

try {
  await client.actions.check({
    agentId: '...',
    action: 'tool_call',
    toolName: 'delete_all',
  });
} catch (error) {
  if (error instanceof AuthorizationError) {
    console.log('Action denied by Guardian');
  } else if (error instanceof TokenExpiredError) {
    console.log('Token expired, re-issue');
  } else if (error instanceof AgentRevokedError) {
    console.log('Agent has been revoked');
  } else if (error instanceof NetworkError) {
    console.log('Gateway unreachable');
  }
}
```

## With Express.js

```typescript
import express from 'express';
import { AgentTrustClient } from '@agenttrustid/sdk';

const client = AgentTrustClient.fromEnv();

async function introspect(req: express.Request, res: express.Response, next: express.NextFunction) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token' });

  // Opaque `at_` tokens are validated by introspection, not signature checks.
  const result = await client.tokens.introspect({ token, target: 'api://my-service' });
  if (!result.active) return res.status(403).json({ error: result.reasoning });

  next();
}

app.get('/protected', introspect, (req, res) => {
  res.json({ message: 'Authorized' });
});
```

## API Reference

### AgentTrustClient

```typescript
const client = new AgentTrustClient({ baseUrl?, authUrl?, auditUrl?, apiKey?, timeout? });
const client = AgentTrustClient.fromEnv();
client.setApiKey('sk_live_...');       // Set API key on all internal HTTP clients
await client.health();                  // { status, service?, version? }
```

### Agents

```typescript
await client.agents.create({ name, framework?, orgId?, capabilities?, metadata? });
await client.agents.list(orgId?);
await client.agents.get(agentId);
await client.agents.revoke(agentId, reason?);  // Revoke an agent and all its credentials
```

### Tokens

```typescript
await client.tokens.issue({ agentId, scopes, ttlSeconds?, sessionId? }, useCache?);
await client.tokens.introspect({ token, target?, requiredScopes? });  // POST /api/v1/agent-tokens/introspect
await client.tokens.revoke(tokenStr, reason?);
client.tokens.clearCache();  // Clear the token cache
```

Tokens are opaque strings prefixed `at_` (e.g. `at_xK3z9...`). They are NOT
JWTs and have no signature. To validate a token, call `introspect`.

Token caching: `issue()` caches matching token requests internally. Cached tokens are reused
if they have more than 30 seconds remaining. Pass `useCache: false` as the second argument to
bypass the cache.

### Actions

```typescript
const result = await client.actions.check({
  agentId,
  action?,           // defaults to 'tool_call'
  toolName,
  toolInputSummary?, // truncated to 200 chars
  sessionId?,
});
// result: { allowed, checkId?, confidence?, guardTier?, latencyMs?, reason? }
```

### Telemetry

```typescript
await client.telemetry.report(agentId, sessionId, events);
// Or auto-batched via AgentTrustGuard.report()
```

### AgentTrustGuard

```typescript
const guard = new AgentTrustGuard(client, agentId, { blockOnDeny?, failOpen?, sessionId? });
const allowed = await guard.check(toolName, inputSummary?);
guard.report(toolName, success?, durationMs?, errorType?);
await guard.flush();
```

### Agent Cards

```typescript
await client.agentCards.generate(agentId);   // Generate a new agent card
await client.agentCards.get(agentId);        // Get the current agent card
await client.agentCards.publish(agentId);    // Publish (make publicly discoverable)
await client.agentCards.getPublic(agentId);  // Get a publicly published card (no auth)
```

### A2A (Agent-to-Agent)

```typescript
await client.a2a.sendTask({ sourceAgentId, targetAgentId, message });
await client.a2a.getTask(taskId);
await client.a2a.cancelTask(taskId);
```

### MCP (Model Context Protocol)

```typescript
await client.mcp.registerServer({ name, url, capabilities? });
await client.mcp.listServers();
await client.mcp.removeServer(serverId);
await client.mcp.callTool(serverId, method, params?);
```

### Delegations

```typescript
await client.delegations.create({
  fromAgentId, toAgentId, scope,
  ttlSeconds?, restrictions?, parentDelegationId?,
});
await client.delegations.list();
await client.delegations.revoke(delegationId);
await client.delegations.initSession(delegationId);
```

### Sessions

```typescript
await client.sessions.initSession(agentId, serverId);
await client.sessions.getSession(sessionId);
await client.sessions.initApiSession(token); // or { token }
```

### Federation

```typescript
await client.federation.registerProvider({ issuer, name, trustLevel? });
await client.federation.listProviders();
await client.federation.deleteProvider(providerId);
await client.federation.verifyToken({ token, issuerHint? });
await client.federation.initSession({ token, issuerHint? });
await client.federation.issueIDToken(agentId, { audience?, nonce?, ttl? });
```

### SIEM Streaming

```typescript
await client.streaming.create({
  name,
  destinationType,
  endpointUrl,
  authToken?,
  batchSize?,
  flushIntervalSeconds?,
  filterEventTypes?,
});
await client.streaming.list();
await client.streaming.get(destinationId);
await client.streaming.update(destinationId, { isActive?, endpointUrl?, authToken? });
await client.streaming.delete(destinationId);
await client.streaming.deliveryLog(destinationId);
await client.streaming.test(destinationId);
```

## Integrations

The SDK ships two optional framework integrations. Both rely on **peer
dependencies** that are NOT installed by default - install only what you
use. The corresponding SDK exports always import cleanly; the peer dep is
only loaded when you instantiate the integration.

### LangChainJS

```bash
npm install @langchain/core
```

```typescript
import { AgentTrustClient, AgentTrustLangChainHandler } from '@agenttrustid/sdk';

const client = AgentTrustClient.fromEnv();
const handler = new AgentTrustLangChainHandler(client, 'agent-id', { blockOnDeny: true });
await agentExecutor.invoke({ input: 'find me ...' }, { callbacks: [handler] });
```

`handleToolStart` checks every tool call through Fast Guard.
`handleToolEnd` / `handleToolError` report telemetry. `handleChainEnd`
flushes telemetry on the top-level chain.

### Vercel AI SDK

```bash
npm install ai
```

```typescript
import { openai } from '@ai-sdk/openai';
import { generateText } from 'ai';
import { AgentTrustClient, withAgentTrustVercelAI } from '@agenttrustid/sdk';

const client = AgentTrustClient.fromEnv();
const model = withAgentTrustVercelAI(openai('gpt-4o'), { client, agentId: 'agent-1' });
const { text } = await generateText({ model, tools, prompt: 'do the thing' });
```

The wrapper applies `LanguageModelV1Middleware` so every tool call the model
emits is pre-flighted by Guardian. Denied calls are stripped from the model
output (and surfaced as a denial line) so the agent loop continues
gracefully instead of crashing.

## Requirements

- Node.js >= 18.0.0 (native `fetch`)
- Zero required runtime dependencies
- Optional peer deps: `@langchain/core` (LangChainJS callback), `ai` (Vercel AI SDK middleware)

## License

Apache License 2.0 - see [LICENSE](./LICENSE) in this directory.
