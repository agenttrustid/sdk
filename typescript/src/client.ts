/**
 * AgentTrust SDK Client
 */

import {
  Agent,
  Token,
  IntrospectionResult,
  CreateAgentRequest,
  IssueTokenRequest,
  IntrospectTokenRequest,
  ActionCheckRequest,
  ActionCheckResult,
  TelemetryEvent,
  AgentTrustGuardOptions,
  AgentTrustClientOptions,
  HealthResponse,
  AgentStatus,
  AgentCard,
  A2ATask,
  A2AMessageTask,
  SendTaskRequest,
  SendMessageRequest,
  MCPServer,
  RegisterMCPServerRequest,
  Delegation,
  CreateDelegationRequest,
  Session,
  InitAPISessionRequest,
  ApprovalRequest,
  FederationProvider,
  RegisterFederationProviderRequest,
  VerifyFederatedTokenRequest,
  VerifyFederatedTokenResult,
  IssueFederatedIDTokenRequest,
  IssueFederatedIDTokenResult,
  SIEMDestination,
  CreateSIEMDestinationRequest,
  UpdateSIEMDestinationRequest,
  SIEMDeliveryRecord,
  IssueWIMSETokenRequest,
  WIMSETokenResponse,
  VerifyWIMSETokenRequest,
  VerifyWIMSETokenResponse,
  ChallengeResponse,
} from './types';
import { generateAgentKey, KeyStore } from './keys';
import { mintDPoPProofWithKeyStore } from './dpop';
import {
  AgentTrustError,
  AuthenticationError,
  AuthorizationError,
  NetworkError,
  ValidationError,
} from './errors';
// Node's global `crypto` is only defined from Node 19+. Importing randomUUID
// from the crypto module keeps the SDK working on the supported Node 18 LTS.
import { randomUUID } from 'crypto';

/**
 * Simple HTTP client using native fetch
 */
class HttpClient {
  private baseUrl: string;
  private timeout: number;
  private headers: Record<string, string>;

  constructor(baseUrl: string, timeout: number = 30000) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.timeout = timeout;
    this.headers = { 'Content-Type': 'application/json' };
  }

  setAuth(token: string): void {
    this.headers['Authorization'] = `Bearer ${token}`;
  }

  setApiKey(key: string): void {
    this.headers['X-API-Key'] = key;
  }

  setHeader(key: string, value: string): void {
    this.headers[key] = value;
  }

  removeHeader(key: string): void {
    delete this.headers[key];
  }

  getBaseUrl(): string {
    return this.baseUrl;
  }

  async request<T>(
    method: string,
    path: string,
    data?: unknown,
    extraHeaders?: Record<string, string>,
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url, {
        method,
        headers: extraHeaders ? { ...this.headers, ...extraHeaders } : this.headers,
        body: data ? JSON.stringify(data) : undefined,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorBody = await response.text();
        let errorData: { message?: string; error?: string } = {};
        try {
          errorData = JSON.parse(errorBody);
        } catch {
          errorData = { message: errorBody };
        }

        const message = errorData.message || errorData.error || `HTTP ${response.status} error`;

        switch (response.status) {
          case 401:
            throw new AuthenticationError(message);
          case 403:
            throw new AuthorizationError(message);
          case 400:
            throw new ValidationError(message, errorData as Record<string, unknown>);
          default:
            throw new AgentTrustError(message, `HTTP_${response.status}`);
        }
      }

      const text = await response.text();
      return text ? JSON.parse(text) : ({} as T);
    } catch (error) {
      clearTimeout(timeoutId);
      if (error instanceof AgentTrustError) throw error;
      if (error instanceof Error && error.name === 'AbortError') {
        throw new NetworkError('Request timeout');
      }
      throw new NetworkError(error instanceof Error ? error.message : 'Unknown network error');
    }
  }

  get<T>(path: string): Promise<T> {
    return this.request<T>('GET', path);
  }

  post<T>(path: string, data?: unknown, extraHeaders?: Record<string, string>): Promise<T> {
    return this.request<T>('POST', path, data, extraHeaders);
  }

  put<T>(path: string, data?: unknown): Promise<T> {
    return this.request<T>('PUT', path, data);
  }

  delete<T>(path: string): Promise<T> {
    return this.request<T>('DELETE', path);
  }
}

/**
 * Parse API response to Agent
 */
function parseAgent(data: Record<string, unknown>): Agent {
  return {
    id: data.id as string,
    name: data.name as string,
    orgId: data.org_id as string,
    framework: (data.framework as Agent['framework']) || 'custom',
    publicKey: data.public_key as string,
    status: (data.status as AgentStatus) || 'active',
    capabilities: (data.capabilities as string[]) || [],
    metadata: (data.metadata as Record<string, unknown>) || {},
    createdAt: data.created_at ? new Date(data.created_at as string) : undefined,
    privateKey: data.private_key as string | undefined,
  };
}

/**
 * Parse API response to Token (opaque `at_` string).
 */
function parseToken(data: Record<string, unknown>): Token {
  return {
    token: (data.token as string) || (data.agent_token as string),
    agentId: data.agent_id as string,
    scopes: (data.scope as string[]) || (data.scopes as string[]) || [],
    audience: (data.audience as string[]) || [],
    issuedAt: new Date((data.issued_at as string) || Date.now()),
    expiresAt: new Date(data.expires_at as string),
    tokenId: (data.token_id as string) || (data.id as string),
  };
}

/**
 * Agents API
 */
export class AgentsAPI {
  private http: HttpClient;

  constructor(http: HttpClient) {
    this.http = http;
  }

  /**
   * Register a new agent.
   *
   * By default the SDK generates an Ed25519 identity keypair on this machine and
   * registers only the public key; the returned `Agent.privateKey` holds the
   * private key, which never leaves this process — persist it in a KeyStore. To
   * bring your own key, set `request.publicKey`. The platform does not issue
   * certificates; use {@link TokensAPI.issue} afterwards to mint opaque `at_`
   * tokens for the agent.
   */
  async create(request: CreateAgentRequest): Promise<Agent> {
    // Generate an identity keypair client-side when the caller didn't supply a
    // public key, so the private key never leaves this process.
    let publicKeyPem = request.publicKey;
    let generatedPrivateKeyPem: string | undefined;
    if (!publicKeyPem) {
      const kp = generateAgentKey();
      publicKeyPem = kp.publicKeyPem;
      generatedPrivateKeyPem = kp.privateKeyPem;
    }

    const data = {
      name: request.name,
      framework: request.framework || 'custom',
      org_id: request.orgId,
      capabilities: request.capabilities || [],
      metadata: request.metadata || {},
      public_key: publicKeyPem,
    };

    const result = await this.http.post<Record<string, unknown>>('/api/v1/agents', data);
    // API may wrap response in {"agent": {...}}
    const agentData = (result.agent as Record<string, unknown>) || result;
    const agent = parseAgent(agentData);
    // When we generated the keypair locally, the private key stays here and is
    // never round-tripped through the platform.
    if (generatedPrivateKeyPem) {
      agent.privateKey = generatedPrivateKeyPem;
    }
    return agent;
  }

  /**
   * Get agent by ID
   */
  async get(agentId: string): Promise<Agent> {
    const result = await this.http.get<Record<string, unknown>>(`/api/v1/agents/${agentId}`);
    return parseAgent(result);
  }

  /**
   * List all agents
   */
  async list(orgId?: string): Promise<Agent[]> {
    const path = orgId ? `/api/v1/agents?org_id=${orgId}` : '/api/v1/agents';
    const result = await this.http.get<{ agents?: unknown[] } | unknown[]>(path);

    const agents = Array.isArray(result) ? result : result.agents || [];
    return agents.map((a) => parseAgent(a as Record<string, unknown>));
  }

  /**
   * Revoke an agent and all its credentials
   */
  async revoke(agentId: string, reason: string = 'manual_revocation'): Promise<boolean> {
    await this.http.post(`/api/v1/agents/${agentId}/revoke`, { reason });
    return true;
  }
}

/**
 * Tokens API
 */
export class TokensAPI {
  private http: HttpClient;
  private authHttp: HttpClient;
  private cache: Map<string, Token> = new Map();

  constructor(http: HttpClient, authHttp?: HttpClient) {
    this.http = http;
    this.authHttp = authHttp || http;
  }

  /**
   * Issue a new opaque agent token (prefix `at_`).
   *
   * Tokens are random opaque strings — not JWTs. They have no signature and
   * cannot be validated client-side. To check a token, call
   * {@link TokensAPI.introspect}.
   */
  async issue(request: IssueTokenRequest, useCache: boolean = true): Promise<Token> {
    const cacheKey = `${request.agentId}:${[...request.scopes].sort().join(':')}:${request.target || ''}:${request.sessionId || ''}`;

    // Check cache
    if (useCache) {
      const cached = this.cache.get(cacheKey);
      if (cached && this.getTtlSeconds(cached) > 30) {
        return cached;
      }
    }

    const data = {
      agent_id: request.agentId,
      scopes: request.scopes,
      ttl: request.ttlSeconds || 300,
      session_id: request.sessionId,
    };

    const result = await this.authHttp.post<Record<string, unknown>>('/api/v1/agent-tokens/issue', data);
    const token = parseToken(result);

    // Cache token
    if (useCache) {
      this.cache.set(cacheKey, token);
    }

    return token;
  }

  /**
   * Introspect an opaque agent token.
   *
   * Sends the token to `POST /api/v1/agent-tokens/introspect` for server-side
   * validation. Returns `{ active, agentId, orgId, scopes, expiresAt, ... }`.
   */
  async introspect(request: IntrospectTokenRequest): Promise<IntrospectionResult> {
    const data = {
      token: request.token,
      target: request.target,
      required_scopes: request.requiredScopes || [],
    };

    const result = await this.authHttp.post<Record<string, unknown>>(
      '/api/v1/agent-tokens/introspect',
      data,
    );

    return {
      active: result.active as boolean,
      agentId: result.agent_id as string | undefined,
      orgId: result.org_id as string | undefined,
      scopes: (result.scopes as string[]) || [],
      expiresAt: result.expires_at ? new Date(result.expires_at as string) : undefined,
      reasoning: result.reasoning as string | undefined,
      guardTier: result.guard_tier as IntrospectionResult['guardTier'],
      confidence: result.confidence as number | undefined,
      latencyMs: result.latency_ms as number | undefined,
    };
  }

  /** @deprecated Use {@link TokensAPI.introspect}. */
  async verify(request: IntrospectTokenRequest): Promise<IntrospectionResult> {
    return this.introspect(request);
  }

  /**
   * Revoke an opaque agent token.
   */
  async revoke(token: string, reason: string = 'manual_revocation'): Promise<boolean> {
    await this.authHttp.post('/api/v1/agent-tokens/revoke', { token, reason });
    // Clear from cache
    for (const [key, cached] of this.cache.entries()) {
      if (cached.token === token) {
        this.cache.delete(key);
      }
    }
    return true;
  }

  /**
   * Clear token cache
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Get seconds until token expires
   */
  private getTtlSeconds(token: Token): number {
    const now = Date.now();
    const expires = token.expiresAt.getTime();
    return Math.max(0, Math.floor((expires - now) / 1000));
  }
}

/**
 * Actions API — Pre-flight authorization checks
 */
export class ActionsAPI {
  private http: HttpClient;
  private agentCreds?: AgentCredentials;

  constructor(http: HttpClient) {
    this.http = http;
  }

  /**
   * Route runtime authorization checks through an agent's WIMSE token plus a
   * per-request DPoP proof (sender-constrained), in addition to any org API key.
   */
  setAgentCredentials(ac: AgentCredentials): void {
    this.agentCreds = ac;
  }

  /**
   * Check if a tool call is authorized (Fast Guard, <15ms)
   */
  async check(request: ActionCheckRequest): Promise<ActionCheckResult> {
    const data: Record<string, unknown> = {
      agent_id: request.agentId,
      session_id: request.sessionId || '',
      action_name: request.toolName || request.action || 'tool_call',
      action_source: 'api',
      action_input_summary: request.toolInputSummary
        ? request.toolInputSummary.slice(0, 200)
        : '',
    };
    if (request.actionEffect) {
      data.action_effect = request.actionEffect;
    }

    const checkPath = '/api/v1/agenttrust/check';
    const extraHeaders = this.agentCreds
      ? await this.agentCreds.runtimeHeaders('POST', checkPath)
      : undefined;
    const result = await this.http.post<Record<string, unknown>>(checkPath, data, extraHeaders);

    return {
      allowed: result.allowed as boolean,
      checkId: result.check_id as string | undefined,
      confidence: result.confidence as number | undefined,
      guardTier: result.guard_tier as ActionCheckResult['guardTier'],
      latencyMs: result.latency_ms as number | undefined,
      reason: result.reason as string | undefined,
      elevationRequired: result.elevation_required as boolean | undefined,
      approvalId: result.approval_id as string | undefined,
    };
  }
}

/**
 * Telemetry API — Report agent behavior to audit trail
 */
export class TelemetryAPI {
  private http: HttpClient;

  constructor(http: HttpClient) {
    this.http = http;
  }

  /**
   * Report a batch of telemetry events
   */
  async report(
    agentId: string,
    sessionId: string,
    events: TelemetryEvent[]
  ): Promise<{ accepted: boolean; events_processed: number }> {
    return this.http.post('/api/v1/telemetry/report', {
      agent_id: agentId,
      session_id: sessionId,
      events,
    });
  }
}

/**
 * AgentTrust ID Guard — Simple pre-flight check + telemetry for any agent.
 *
 * For agents using raw OpenAI/Anthropic SDKs.
 *
 * @example
 * ```typescript
 * const guard = new AgentTrustGuard(client, 'agent-id');
 *
 * await guard.check('web_search', 'query about AI');  // throws if denied
 * const result = await doWebSearch(query);
 * guard.report('web_search', true, 1200);  // fire-and-forget telemetry
 *
 * guard.flush();  // when done
 * ```
 */
export class AgentTrustGuard {
  private client: AgentTrustClient;
  private agentId: string;
  private sessionId: string;
  private blockOnDeny: boolean;
  private failOpen: boolean;
  private eventBuffer: TelemetryEvent[] = [];

  constructor(client: AgentTrustClient, agentId: string, options: AgentTrustGuardOptions = {}) {
    this.client = client;
    this.agentId = agentId;
    this.sessionId = options.sessionId || randomUUID();
    this.blockOnDeny = options.blockOnDeny ?? true;
    this.failOpen = options.failOpen ?? false;
  }

  /**
   * Pre-flight check before a tool call.
   * Returns true if allowed, throws AgentTrustError if denied (when blockOnDeny=true).
   * When elevation is required, throws with code 'ELEVATION_REQUIRED' and details.approvalId.
   */
  async check(toolName: string, inputSummary: string = '', actionEffect: string = ''): Promise<boolean> {
    try {
      const request: ActionCheckRequest = {
        agentId: this.agentId,
        toolName,
        toolInputSummary: inputSummary,
        sessionId: this.sessionId,
      };
      if (actionEffect) {
        request.actionEffect = actionEffect;
      }

      const result = await this.client.actions.check(request);

      if (!result.allowed) {
        if (this.blockOnDeny) {
          if (result.elevationRequired) {
            throw new AgentTrustError(
              `Tool '${toolName}' requires elevation: ${result.reason}`,
              'ELEVATION_REQUIRED',
              { approvalId: result.approvalId }
            );
          }
          throw new AgentTrustError(
            `Tool '${toolName}' denied: ${result.reason}`,
            'ACTION_DENIED'
          );
        }
        return false;
      }
      return true;
    } catch (error) {
      // Re-throw denial/auth errors — these are real policy decisions
      if (error instanceof AgentTrustError && error.code !== 'NETWORK_ERROR') throw error;
      // Network errors respect failOpen setting
      if (!this.failOpen) {
        throw new AgentTrustError(
          `Guardian unreachable: ${error instanceof Error ? error.message : error}`,
          'GUARDIAN_UNAVAILABLE'
        );
      }
      return true;
    }
  }

  /**
   * Report a tool call result (buffered, sent on flush).
   */
  report(
    toolName: string,
    success: boolean = true,
    durationMs: number = 0,
    errorType?: string
  ): void {
    const event: TelemetryEvent = {
      event_type: success ? 'tool_end' : 'tool_error',
      tool_name: toolName,
      duration_ms: durationMs,
      success,
      timestamp: new Date().toISOString(),
    };
    if (errorType) event.error_type = errorType;
    this.eventBuffer.push(event);

    // Auto-flush at 10 events
    if (this.eventBuffer.length >= 10) {
      this.flush().catch(() => {});
    }
  }

  /**
   * Flush all buffered telemetry events.
   */
  async flush(): Promise<void> {
    if (this.eventBuffer.length === 0) return;
    const events = [...this.eventBuffer];
    this.eventBuffer = [];
    try {
      await this.client.telemetry.report(this.agentId, this.sessionId, events);
    } catch (error) {
      // Best-effort — don't crash the agent
      console.warn('AgentTrust ID telemetry flush failed:', error);
    }
  }
}

/**
 * Parse API response to AgentCard
 */
/**
 * Parse an A2A v1.0 Agent Card.
 *
 * Every v1.0 field is optional: if `supportedInterfaces`, `signatures`, the
 * legacy `url`, or any other field is missing the parser leaves it `undefined`
 * rather than throwing, so older cached cards still parse.
 */
function parseAgentCard(data: Record<string, unknown>): AgentCard {
  const capabilities = (data.capabilities as Record<string, unknown>) || {};
  const skills = (data.skills as Array<Record<string, unknown>>) || [];
  const provider = data.provider as Record<string, unknown> | undefined;
  const supportedInterfaces = data.supportedInterfaces as
    | Array<Record<string, unknown>>
    | undefined;
  const extensions = capabilities.extensions as
    | Array<Record<string, unknown>>
    | undefined;
  const signatures = data.signatures as Array<Record<string, unknown>> | undefined;

  const card: AgentCard = {
    name: data.name as string,
    description: data.description as string | undefined,
    version: data.version as string,
    capabilities: {
      streaming: (capabilities.streaming as boolean) || false,
      pushNotifications: (capabilities.push_notifications as boolean)
        || (capabilities.pushNotifications as boolean)
        || false,
      extendedAgentCard: capabilities.extendedAgentCard as boolean | undefined,
      ...(extensions
        ? {
            extensions: extensions.map((e) => ({
              uri: e.uri as string,
              description: e.description as string | undefined,
              required: e.required as boolean | undefined,
              params: e.params as Record<string, unknown> | undefined,
            })),
          }
        : {}),
    },
    skills: skills.map((s) => ({
      id: s.id as string,
      name: s.name as string,
      description: (s.description as string) || '',
      tags: (s.tags as string[]) || [],
      examples: s.examples as string[] | undefined,
      inputModes: s.inputModes as string[] | undefined,
      outputModes: s.outputModes as string[] | undefined,
    })),
    defaultInputModes: data.defaultInputModes as string[] | undefined,
    defaultOutputModes: data.defaultOutputModes as string[] | undefined,
    securitySchemes: data.securitySchemes as
      | Record<string, { type: string; scheme?: string }>
      | undefined,
    securityRequirements: data.securityRequirements as
      | Record<string, string[]>[]
      | undefined,
    documentationUrl: data.documentationUrl as string | undefined,
    iconUrl: data.iconUrl as string | undefined,
    url: data.url as string | undefined,
  };

  if (provider) {
    card.provider = {
      organization: provider.organization as string,
      url: provider.url as string | undefined,
    };
  }

  if (supportedInterfaces) {
    card.supportedInterfaces = supportedInterfaces.map((i) => ({
      url: i.url as string,
      protocolBinding: i.protocolBinding as string,
      protocolVersion: i.protocolVersion as string,
      tenant: i.tenant as string | undefined,
    }));
  }

  if (signatures) {
    card.signatures = signatures.map((s) => ({
      protected: s.protected as string,
      signature: s.signature as string,
      header: s.header as Record<string, unknown> | undefined,
    }));
  }

  return card;
}

/** URI identifying the AgentTrust trust capability extension on a v1.0 card. */
export const TRUST_EXTENSION_URI = 'https://agenttrust.id/ext/trust/v1';

/**
 * Resolve the primary transport URL of an Agent Card: the first
 * `supportedInterfaces` URL (A2A v1.0), falling back to the legacy top-level
 * `url` on older cached cards.
 */
export function primaryUrl(card: AgentCard): string | undefined {
  return card.supportedInterfaces?.[0]?.url ?? card.url;
}

/**
 * Read the AgentTrust trust score from a v1.0 Agent Card's trust capability
 * extension (`params.ati_trust_score`). Returns 0 when the extension or the
 * score is absent.
 */
export function trustScore(card: AgentCard): number {
  const ext = card.capabilities.extensions?.find(
    (e) => e.uri === TRUST_EXTENSION_URI
  );
  const score = ext?.params?.ati_trust_score;
  return typeof score === 'number' ? score : 0;
}

/**
 * Parse API response to A2ATask
 */
function parseA2ATask(data: Record<string, unknown>): A2ATask {
  return {
    id: data.id as string,
    sourceAgentId: (data.source_agent_id as string) || (data.sourceAgentId as string),
    targetAgentId: (data.target_agent_id as string) || (data.targetAgentId as string),
    status: data.status as string,
    message: data.message as Record<string, unknown> | undefined,
    artifacts: data.artifacts as unknown[] | undefined,
    metadata: data.metadata as Record<string, unknown> | undefined,
    createdAt: (data.created_at as string) || (data.createdAt as string),
    updatedAt: (data.updated_at as string) || (data.updatedAt as string),
  };
}

/**
 * Parse an A2A v1.0 Task returned by the `message/send` method.
 */
function parseA2AMessageTask(data: Record<string, unknown>): A2AMessageTask {
  const status = (data.status as Record<string, unknown>) || {};
  return {
    id: data.id as string,
    contextId: (data.contextId as string) || (data.context_id as string),
    status: {
      state: status.state as string,
      timestamp: status.timestamp as string | undefined,
    },
    history: data.history as Record<string, unknown>[] | undefined,
    artifacts: data.artifacts as unknown[] | undefined,
  };
}

/**
 * Parse API response to MCPServer
 */
function parseMCPServer(data: Record<string, unknown>): MCPServer {
  return {
    id: data.id as string,
    name: data.name as string,
    url: data.url as string,
    capabilities: data.capabilities as string[] | undefined,
    orgId: (data.org_id as string) || (data.orgId as string),
    createdAt: (data.created_at as string) || (data.createdAt as string),
  };
}

/**
 * Parse API response to Delegation
 */
function parseDelegation(data: Record<string, unknown>): Delegation {
  const delegation = (data.delegation as Record<string, unknown>) || data;
  return {
    id: delegation.id as string,
    fromAgentId: (delegation.from_agent_id as string) || (delegation.fromAgentId as string),
    toAgentId: (delegation.to_agent_id as string) || (delegation.toAgentId as string),
    orgId: (delegation.org_id as string) || (delegation.orgId as string),
    scope: (delegation.scope as string[]) || [],
    restrictions: delegation.restrictions as Record<string, unknown> | undefined,
    delegationChain: (delegation.delegation_chain as string[])
      || (delegation.delegationChain as string[]),
    expiresAt: (delegation.expires_at as string) || (delegation.expiresAt as string),
    revokedAt: (delegation.revoked_at as string) || (delegation.revokedAt as string),
    createdAt: (delegation.created_at as string) || (delegation.createdAt as string),
  };
}

/**
 * Parse API response to Session
 */
function parseSession(data: Record<string, unknown>): Session {
  return {
    sessionId: (data.session_id as string) || (data.sessionId as string),
    agentId: (data.agent_id as string) || (data.agentId as string),
    orgId: (data.org_id as string) || (data.orgId as string),
    source: data.source as string,
    serverId: (data.server_id as string) || (data.serverId as string),
    delegationId: (data.delegation_id as string) || (data.delegationId as string),
    providerId: (data.provider_id as string) || (data.providerId as string),
    issuer: data.issuer as string | undefined,
    trustLevel: (data.trust_level as string) || (data.trustLevel as string),
    mode: data.mode as string,
    allowedActions: (data.allowed_actions as string[]) || (data.allowedActions as string[]) || [],
    scopeCeiling: (data.scope_ceiling as string[]) || (data.scopeCeiling as string[]) || [],
    totalCalls: (data.total_calls as number) || (data.totalCalls as number) || 0,
    readCalls: (data.read_calls as number) || (data.readCalls as number) || 0,
    writeCalls: (data.write_calls as number) || (data.writeCalls as number) || 0,
    deniedCalls: (data.denied_calls as number) || (data.deniedCalls as number) || 0,
    createdAt: (data.created_at as string) || (data.createdAt as string),
    lastActivityAt: (data.last_activity_at as string) || (data.lastActivityAt as string),
  };
}

/**
 * Parse API response to ApprovalRequest
 */
function parseApprovalRequest(data: Record<string, unknown>): ApprovalRequest {
  return {
    id: data.id as string,
    sessionId: (data.session_id as string) || (data.sessionId as string),
    agentId: (data.agent_id as string) || (data.agentId as string),
    orgId: (data.org_id as string) || (data.orgId as string),
    actionName: (data.action_name as string) || (data.actionName as string),
    actionEffect: (data.action_effect as string) || (data.actionEffect as string),
    status: data.status as string,
    createdAt: (data.created_at as string) || (data.createdAt as string),
    expiresAt: (data.expires_at as string) || (data.expiresAt as string),
    decidedBy: (data.decided_by as string) || (data.decidedBy as string),
  };
}

function parseFederationProvider(data: Record<string, unknown>): FederationProvider {
  const provider = (data.provider as Record<string, unknown>) || data;
  return {
    id: provider.id as string,
    orgId: (provider.org_id as string) || (provider.orgId as string),
    issuer: provider.issuer as string,
    name: provider.name as string,
    jwksUri: (provider.jwks_uri as string) || (provider.jwksUri as string),
    authorizationEndpoint: (provider.authorization_endpoint as string)
      || (provider.authorizationEndpoint as string),
    tokenEndpoint: (provider.token_endpoint as string) || (provider.tokenEndpoint as string),
    trustLevel: (provider.trust_level as string) || (provider.trustLevel as string) || 'standard',
    status: (provider.status as string) || 'active',
    createdAt: (provider.created_at as string) || (provider.createdAt as string),
    updatedAt: (provider.updated_at as string) || (provider.updatedAt as string),
  };
}

function parseVerifyFederatedTokenResult(data: Record<string, unknown>): VerifyFederatedTokenResult {
  return {
    valid: data.valid as boolean,
    agentId: (data.agent_id as string) || (data.agentId as string),
    issuer: data.issuer as string | undefined,
    expiresAt: (data.expires_at as string) || (data.expiresAt as string),
    error: data.error as string | undefined,
  };
}

function parseIssueFederatedIDTokenResult(data: Record<string, unknown>): IssueFederatedIDTokenResult {
  return {
    idToken: (data.id_token as string) || (data.idToken as string) || (data.token as string),
    token: data.token as string | undefined,
    expiresIn: (data.expires_in as number) || (data.expiresIn as number) || 0,
    expiresAt: (data.expires_at as string) || (data.expiresAt as string),
  };
}

function parseSIEMDestination(data: Record<string, unknown>): SIEMDestination {
  return {
    id: data.id as string,
    orgId: (data.org_id as string) || (data.orgId as string),
    name: data.name as string,
    destinationType: (data.destination_type as string) || (data.destinationType as string),
    endpointUrl: (data.endpoint_url as string) || (data.endpointUrl as string),
    authToken: (data.auth_token as string) || (data.authToken as string),
    isActive: (data.is_active as boolean) ?? (data.isActive as boolean) ?? false,
    batchSize: (data.batch_size as number) || (data.batchSize as number) || 0,
    flushIntervalSeconds: (data.flush_interval_seconds as number)
      || (data.flushIntervalSeconds as number)
      || 0,
    filterEventTypes: (data.filter_event_types as string[]) || (data.filterEventTypes as string[]),
    createdAt: (data.created_at as string) || (data.createdAt as string),
    updatedAt: (data.updated_at as string) || (data.updatedAt as string),
  };
}

function parseSIEMDeliveryRecord(data: Record<string, unknown>): SIEMDeliveryRecord {
  return {
    id: data.id as string,
    destinationId: (data.destination_id as string) || (data.destinationId as string),
    batchSize: (data.batch_size as number) || (data.batchSize as number) || 0,
    status: data.status as string,
    statusCode: (data.status_code as number) || (data.statusCode as number),
    errorMessage: (data.error_message as string) || (data.errorMessage as string),
    deliveredAt: (data.delivered_at as string) || (data.deliveredAt as string),
  };
}

/**
 * Agent Cards API — Generate and publish A2A-compatible agent cards
 */
export class AgentCardsAPI {
  private http: HttpClient;

  constructor(http: HttpClient) {
    this.http = http;
  }

  /**
   * Generate a new agent card for the given agent
   */
  async generate(agentId: string): Promise<AgentCard> {
    const result = await this.http.post<Record<string, unknown>>(
      `/api/v1/agents/${agentId}/card`
    );
    return parseAgentCard(result);
  }

  /**
   * Get the current agent card
   */
  async get(agentId: string): Promise<AgentCard> {
    const result = await this.http.get<Record<string, unknown>>(
      `/api/v1/agents/${agentId}/card`
    );
    return parseAgentCard(result);
  }

  /**
   * Publish an agent card (makes it publicly discoverable)
   */
  async publish(agentId: string): Promise<AgentCard> {
    const result = await this.http.request<Record<string, unknown>>(
      'PUT',
      `/api/v1/agents/${agentId}/card/publish`
    );
    return parseAgentCard(result);
  }

  /**
   * Get a publicly published agent card (no authentication required)
   */
  async getPublic(agentId: string): Promise<AgentCard> {
    const result = await this.http.get<Record<string, unknown>>(
      `/a2a/agents/${agentId}/agent.json`
    );
    return parseAgentCard(result);
  }
}

/**
 * A2A API — Agent-to-Agent task dispatch via JSON-RPC 2.0
 */
export class A2AAPI {
  private http: HttpClient;
  private requestId: number = 0;

  constructor(http: HttpClient) {
    this.http = http;
  }

  /**
   * Make a JSON-RPC 2.0 call to an A2A endpoint (defaults to the shared `/a2a`).
   */
  private async jsonRpc(
    method: string,
    params: unknown,
    endpoint: string = '/a2a'
  ): Promise<Record<string, unknown>> {
    this.requestId++;
    const body = {
      jsonrpc: '2.0',
      method,
      params,
      id: String(this.requestId),
    };

    const result = await this.http.post<Record<string, unknown>>(endpoint, body);

    if (result.error) {
      const err = result.error as Record<string, unknown>;
      throw new AgentTrustError(
        (err.message as string) || 'A2A RPC error',
        `A2A_ERROR_${err.code || 'UNKNOWN'}`
      );
    }

    return result.result as Record<string, unknown>;
  }

  /**
   * Send a task from one agent to another
   */
  async sendTask(params: SendTaskRequest): Promise<A2ATask> {
    const result = await this.jsonRpc('tasks/send', {
      source_agent_id: params.sourceAgentId,
      target_agent_id: params.targetAgentId,
      message: params.message,
    });
    return parseA2ATask(result);
  }

  /**
   * Get the status and result of a task
   */
  async getTask(taskId: string): Promise<A2ATask> {
    const result = await this.jsonRpc('tasks/get', { id: taskId });
    return parseA2ATask(result);
  }

  /**
   * Cancel a running task
   */
  async cancelTask(taskId: string): Promise<A2ATask> {
    const result = await this.jsonRpc('tasks/cancel', { id: taskId });
    return parseA2ATask(result);
  }

  /**
   * Send a message to an agent using the A2A v1.0 `message/send` method.
   *
   * Posts JSON-RPC to the per-agent A2A endpoint and returns the v1.0 Task.
   */
  async sendMessage(
    agentId: string,
    params: SendMessageRequest
  ): Promise<A2AMessageTask> {
    const message: Record<string, unknown> = {
      role: 'user',
      parts: [{ kind: 'text', text: params.text }],
      messageId: params.messageId ?? randomUUID(),
      ...(params.taskId ? { taskId: params.taskId } : {}),
    };
    const result = await this.jsonRpc(
      'message/send',
      { message },
      `/a2a/agents/${agentId}`
    );
    return parseA2AMessageTask(result);
  }
}

/**
 * MCP API — Register and proxy to MCP servers
 */
export class MCPAPI {
  private http: HttpClient;

  constructor(http: HttpClient) {
    this.http = http;
  }

  /**
   * Register a new MCP server
   */
  async registerServer(params: RegisterMCPServerRequest): Promise<MCPServer> {
    const data = {
      name: params.name,
      url: params.url,
      capabilities: params.capabilities,
    };
    const result = await this.http.post<Record<string, unknown>>('/mcp/servers', data);
    return parseMCPServer(result);
  }

  /**
   * List all registered MCP servers
   */
  async listServers(): Promise<MCPServer[]> {
    const result = await this.http.get<{ servers?: unknown[] } | unknown[]>('/mcp/servers');
    const servers = Array.isArray(result) ? result : (result.servers || []);
    return servers.map((s) => parseMCPServer(s as Record<string, unknown>));
  }

  /**
   * Remove a registered MCP server
   */
  async removeServer(serverId: string): Promise<void> {
    await this.http.delete(`/mcp/servers/${serverId}`);
  }

  /**
   * Call a tool on an MCP server via the AgentTrust ID proxy.
   *
   * The proxy authorizes the call by agent identity, so `agentId` is required and
   * is sent as the `X-Agent-ID` header — the gateway rejects the request without
   * it. When provided, `sessionId` is sent as `X-Session-ID` for session-scoped
   * authorization.
   *
   * @param serverId  registered MCP server ID
   * @param agentId   ID of the agent making the call (sent as X-Agent-ID; required)
   * @param method    JSON-RPC method (e.g. "tools/call")
   * @param params    JSON-RPC params
   * @param sessionId optional AgentTrust session ID
   */
  async callTool(
    serverId: string,
    agentId: string,
    method: string,
    params?: Record<string, unknown>,
    sessionId?: string
  ): Promise<unknown> {
    if (!agentId) {
      throw new Error(
        'agentId is required: the MCP proxy authorizes the call by agent identity (X-Agent-ID)'
      );
    }
    this.http.setHeader('X-Agent-ID', agentId);
    if (sessionId) {
      this.http.setHeader('X-Session-ID', sessionId);
    }
    try {
      const payload: Record<string, unknown> = {
        jsonrpc: '2.0',
        id: 1,
        method,
      };
      if (params) {
        payload.params = params;
      }
      const result = await this.http.post<Record<string, unknown>>(`/mcp/${serverId}`, payload);
      if (result && result.result !== undefined) {
        return result.result;
      }
      return result;
    } finally {
      this.http.removeHeader('X-Agent-ID');
      if (sessionId) {
        this.http.removeHeader('X-Session-ID');
      }
    }
  }
}

/**
 * Delegations API — Manage capability delegation between agents
 */
export class DelegationsAPI {
  private http: HttpClient;

  constructor(http: HttpClient) {
    this.http = http;
  }

  /**
   * Create a new delegation from one agent to another
   */
  async create(params: CreateDelegationRequest): Promise<Delegation> {
    const data = {
      from_agent_id: params.fromAgentId,
      to_agent_id: params.toAgentId,
      scope: params.scope,
      ttl_seconds: params.ttlSeconds,
      restrictions: params.restrictions,
      parent_delegation_id: params.parentDelegationId,
    };
    const result = await this.http.post<Record<string, unknown>>(
      '/api/v1/delegations',
      data
    );
    return parseDelegation(result);
  }

  /**
   * List all delegations
   */
  async list(): Promise<Delegation[]> {
    const result = await this.http.get<{ delegations?: unknown[] } | unknown[]>(
      '/api/v1/delegations'
    );
    const delegations = Array.isArray(result) ? result : (result.delegations || []);
    return delegations.map((d) => parseDelegation(d as Record<string, unknown>));
  }

  /**
   * Revoke a delegation
   */
  async revoke(delegationId: string): Promise<void> {
    await this.http.delete(`/api/v1/delegations/${delegationId}`);
  }

  /**
   * Initialize an AgentTrust session from an active delegation.
   */
  async initSession(delegationId: string): Promise<Session> {
    const result = await this.http.post<Record<string, unknown>>(
      `/api/v1/delegations/${delegationId}/session`
    );
    return parseSession(result);
  }
}

/**
 * Federation API — OIDC provider registration, verification, and session bridging.
 */
export class FederationAPI {
  private http: HttpClient;

  constructor(http: HttpClient) {
    this.http = http;
  }

  async registerProvider(request: RegisterFederationProviderRequest): Promise<FederationProvider> {
    const result = await this.http.post<Record<string, unknown>>('/api/v1/federation/providers', {
      issuer: request.issuer,
      name: request.name,
      trust_level: request.trustLevel,
    });
    return parseFederationProvider(result);
  }

  async listProviders(): Promise<FederationProvider[]> {
    const result = await this.http.get<{ providers?: unknown[] } | unknown[]>(
      '/api/v1/federation/providers'
    );
    const providers = Array.isArray(result) ? result : (result.providers || []);
    return providers.map((provider) => parseFederationProvider(provider as Record<string, unknown>));
  }

  async deleteProvider(providerId: string): Promise<void> {
    await this.http.delete(`/api/v1/federation/providers/${providerId}`);
  }

  async verifyToken(request: VerifyFederatedTokenRequest): Promise<VerifyFederatedTokenResult> {
    const result = await this.http.post<Record<string, unknown>>('/api/v1/federation/tokens/verify', {
      token: request.token,
      issuer_hint: request.issuerHint,
    });
    return parseVerifyFederatedTokenResult(result);
  }

  async initSession(request: VerifyFederatedTokenRequest): Promise<Session> {
    const result = await this.http.post<Record<string, unknown>>('/api/v1/federation/sessions/init', {
      token: request.token,
      issuer_hint: request.issuerHint,
    });
    return parseSession(result);
  }

  async issueIDToken(
    agentId: string,
    request: IssueFederatedIDTokenRequest = {}
  ): Promise<IssueFederatedIDTokenResult> {
    const result = await this.http.post<Record<string, unknown>>(
      '/api/v1/federation/tokens/issue',
      {
        agent_id: agentId,
        audience: request.audience,
        scopes: request.scopes || [],
        ttl: request.ttl,
      }
    );
    return parseIssueFederatedIDTokenResult(result);
  }
}

/**
 * Streaming API — SIEM destination management and delivery logs.
 */
export class StreamingAPI {
  private http: HttpClient;

  constructor(http: HttpClient) {
    this.http = http;
  }

  async create(request: CreateSIEMDestinationRequest): Promise<SIEMDestination> {
    const result = await this.http.post<Record<string, unknown>>('/api/v1/siem/destinations', {
      name: request.name,
      destination_type: request.destinationType,
      endpoint_url: request.endpointUrl,
      auth_token: request.authToken,
      batch_size: request.batchSize,
      flush_interval_seconds: request.flushIntervalSeconds,
      filter_event_types: request.filterEventTypes,
    });
    return parseSIEMDestination(result);
  }

  async list(): Promise<SIEMDestination[]> {
    const result = await this.http.get<{ destinations?: unknown[] } | unknown[]>(
      '/api/v1/siem/destinations'
    );
    const destinations = Array.isArray(result) ? result : (result.destinations || []);
    return destinations.map((destination) => parseSIEMDestination(destination as Record<string, unknown>));
  }

  async get(destinationId: string): Promise<SIEMDestination> {
    const result = await this.http.get<Record<string, unknown>>(
      `/api/v1/siem/destinations/${destinationId}`
    );
    return parseSIEMDestination(result);
  }

  async update(destinationId: string, request: UpdateSIEMDestinationRequest): Promise<SIEMDestination> {
    const result = await this.http.put<Record<string, unknown>>(
      `/api/v1/siem/destinations/${destinationId}`,
      {
        name: request.name,
        endpoint_url: request.endpointUrl,
        auth_token: request.authToken,
        is_active: request.isActive,
        batch_size: request.batchSize,
        flush_interval_seconds: request.flushIntervalSeconds,
        filter_event_types: request.filterEventTypes,
      }
    );
    return parseSIEMDestination(result);
  }

  async delete(destinationId: string): Promise<void> {
    await this.http.delete(`/api/v1/siem/destinations/${destinationId}`);
  }

  async deliveryLog(destinationId: string): Promise<SIEMDeliveryRecord[]> {
    const result = await this.http.get<{ logs?: unknown[] } | unknown[]>(
      `/api/v1/siem/destinations/${destinationId}/logs`
    );
    const logs = Array.isArray(result) ? result : (result.logs || []);
    return logs.map((record) => parseSIEMDeliveryRecord(record as Record<string, unknown>));
  }

  async test(destinationId: string): Promise<Record<string, unknown>> {
    return this.http.post<Record<string, unknown>>(`/api/v1/siem/destinations/${destinationId}/test`);
  }
}

/**
 * Sessions API — AgentTrust session management
 */
export class SessionsAPI {
  private http: HttpClient;

  constructor(http: HttpClient) {
    this.http = http;
  }

  /**
   * Initialize a new AgentTrust session for an MCP server
   */
  async initSession(agentId: string, serverId: string): Promise<Session> {
    const result = await this.http.post<Record<string, unknown>>(
      '/mcp/sessions/init',
      { agent_id: agentId, server_id: serverId }
    );
    return parseSession(result);
  }

  /**
   * Get an existing session by ID
   */
  async getSession(sessionId: string): Promise<Session> {
    const result = await this.http.get<Record<string, unknown>>(
      `/mcp/sessions/${sessionId}`
    );
    return parseSession(result);
  }

  /**
   * Initialize a new AgentTrust session from an AgentTrust ID API token.
   */
  async initApiSession(request: InitAPISessionRequest | string): Promise<Session> {
    const token = typeof request === 'string' ? request : request.token;
    const result = await this.http.post<Record<string, unknown>>(
      '/api/v1/agenttrust/api-sessions/init',
      { token }
    );
    return parseSession(result);
  }
}

/**
 * Approvals API — AgentTrust elevation approval workflow
 */
export class ApprovalsAPI {
  private http: HttpClient;

  constructor(http: HttpClient) {
    this.http = http;
  }

  /**
   * Approve an elevation request
   */
  async approve(
    approvalId: string,
    decidedBy: string = 'sdk'
  ): Promise<Record<string, unknown>> {
    return this.http.post<Record<string, unknown>>(
      `/mcp/approvals/${approvalId}/approve`,
      { decided_by: decidedBy }
    );
  }

  /**
   * Deny an elevation request
   */
  async deny(
    approvalId: string,
    decidedBy: string = 'sdk'
  ): Promise<Record<string, unknown>> {
    return this.http.post<Record<string, unknown>>(
      `/mcp/approvals/${approvalId}/deny`,
      { decided_by: decidedBy }
    );
  }

  /**
   * Get an approval request by ID
   */
  async get(approvalId: string): Promise<ApprovalRequest> {
    const result = await this.http.get<Record<string, unknown>>(
      `/mcp/approvals/${approvalId}`
    );
    return parseApprovalRequest(result);
  }
}

/**
 * AgentTrust ID Client - Main entry point
 *
 * @example
 * ```typescript
 * const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080' });
 *
 * // Create an agent
 * const agent = await client.agents.create({
 *   name: 'my-agent',
 *   framework: 'langchain'
 * });
 *
 * // Issue a token
 * const token = await client.tokens.issue({
 *   agentId: agent.id,
 *   scopes: ['files:read'],
 *   target: 'mcp://filesystem'
 * });
 *
 * // Use token in requests (opaque `at_` token)
 * const headers = { Authorization: `Bearer ${token.token}` };
 *
 * // Validate a token by introspecting it
 * const result = await client.tokens.introspect({ token: token.token });
 * if (result.active) { /* ... *\/ }
 * ```
 */
/**
 * WIMSE workload identity token operations.
 *
 * Issues and verifies SPIFFE-style workload identity tokens (JWTs) for agents,
 * and supports proof-of-possession: an agent proves it holds its registered
 * private key by signing a server challenge, binding the issued token to that
 * key via the RFC 7800 `cnf.jkt` claim.
 */
export class WIMSEAPI {
  private http: HttpClient;

  constructor(http: HttpClient) {
    this.http = http;
  }

  /** Issue a WIMSE workload identity token (`POST /api/v1/wimse/token`). */
  async issueToken(req: IssueWIMSETokenRequest): Promise<WIMSETokenResponse> {
    const body: Record<string, unknown> = { agent_id: req.agentId };
    if (req.serviceName !== undefined) body.service_name = req.serviceName;
    if (req.environment !== undefined) body.environment = req.environment;
    if (req.ttlSeconds !== undefined) body.ttl_seconds = req.ttlSeconds;
    if (req.audience && req.audience.length) body.audience = req.audience;
    if (req.proof) {
      body.proof = { nonce: req.proof.nonce, ts: req.proof.ts, signature: req.proof.signature };
    }
    const r = await this.http.post<Record<string, unknown>>('/api/v1/wimse/token', body);
    return {
      token: (r.token as string) || '',
      workloadId: (r.workload_id as string) || '',
      trustDomain: (r.trust_domain as string) || '',
      expiresAt: (r.expires_at as string) || '',
    };
  }

  /** Verify a WIMSE workload identity token (`POST /api/v1/wimse/verify`). */
  async verifyToken(req: VerifyWIMSETokenRequest): Promise<VerifyWIMSETokenResponse> {
    const body: Record<string, unknown> = { token: req.token };
    if (req.trustDomainFilter) body.trust_domain_filter = req.trustDomainFilter;
    const r = await this.http.post<Record<string, unknown>>('/api/v1/wimse/verify', body);
    return {
      valid: Boolean(r.valid),
      agentId: r.agent_id as string | undefined,
      workloadId: r.workload_id as string | undefined,
      trustDomain: r.trust_domain as string | undefined,
      capabilities: (r.capabilities as string[]) || [],
      reason: r.reason as string | undefined,
    };
  }

  /** Request a single-use proof-of-possession challenge nonce for an agent. */
  async challenge(agentId: string): Promise<ChallengeResponse> {
    const r = await this.http.post<Record<string, unknown>>(
      `/api/v1/agents/${agentId}/challenge`,
    );
    return { nonce: (r.nonce as string) || '', expiresAt: (r.expires_at as string) || '' };
  }

  /**
   * Issue a WIMSE token using proof-of-possession.
   *
   * Fetches a challenge for the agent, signs the canonical challenge message
   * with the agent's key from `keyStore`, and issues with the proof attached so
   * the resulting token is bound to the agent key (`cnf.jkt`). Required when the
   * org enables proof-of-possession.
   */
  async issueTokenWithProof(
    req: IssueWIMSETokenRequest,
    keyStore: KeyStore,
  ): Promise<WIMSETokenResponse> {
    const challenge = await this.challenge(req.agentId);
    const ts = Math.floor(Date.now() / 1000);
    const audience = (req.audience || []).join(',');
    // Canonical message must stay byte-identical to the server's
    // crypto.PoPMessage: "pop-v1:<nonce>:<agentID>:<audience>:<ts>".
    const message = `pop-v1:${challenge.nonce}:${req.agentId}:${audience}:${ts}`;
    const sig = keyStore.sign(req.agentId, new TextEncoder().encode(message));
    const signature = Buffer.from(sig).toString('base64url');
    return this.issueToken({
      ...req,
      proof: { nonce: challenge.nonce, ts, signature },
    });
  }
}

/** Options for {@link AgentCredentials}. */
export interface AgentCredentialsOptions {
  /** WIMSE token audience. */
  audience?: string[];
  /** Requested WIMSE token TTL in seconds (0/undefined = server default). */
  ttlSeconds?: number;
}

/** How long before a WIMSE token's expiry the manager proactively re-issues. */
const CREDENTIAL_REFRESH_SKEW_MS = 60_000;

/**
 * Manages an agent's runtime authentication: auto-issues a WIMSE token via the
 * proof-of-possession flow, caches it, refreshes it before expiry, and produces
 * per-request `Authorization: Bearer` + `DPoP` headers. The private key never
 * leaves the KeyStore — both the PoP signature (at issuance) and the DPoP proof
 * (per request) are signed through it.
 *
 * Build it from a client, then route runtime checks through it:
 *
 * ```ts
 * const ac = new AgentCredentials(client, keyStore, agentId, publicKeyPem);
 * client.useAgentCredentials(ac);
 * await client.actions.check({ agentId, toolName: 'read_file' });
 * ```
 */
export class AgentCredentials {
  private readonly wimse: WIMSEAPI;
  private readonly baseUrl: string;
  private cachedToken = '';
  private expiresAtMs = 0;

  constructor(
    client: AgentTrustClient,
    private readonly ks: KeyStore,
    private readonly agentId: string,
    private readonly publicKeyPem: string,
    private readonly opts: AgentCredentialsOptions = {},
  ) {
    this.wimse = client.wimse;
    this.baseUrl = client.getBaseUrl();
  }

  /**
   * Returns a currently-valid WIMSE token, issuing or refreshing one via the
   * proof-of-possession flow when the cache is empty or near expiry.
   */
  async token(): Promise<string> {
    if (this.cachedToken && this.expiresAtMs - Date.now() > CREDENTIAL_REFRESH_SKEW_MS) {
      return this.cachedToken;
    }
    const resp = await this.wimse.issueTokenWithProof(
      { agentId: this.agentId, audience: this.opts.audience, ttlSeconds: this.opts.ttlSeconds },
      this.ks,
    );
    this.cachedToken = resp.token;
    this.expiresAtMs = parseTokenExpiry(resp.expiresAt);
    return this.cachedToken;
  }

  /**
   * Returns the headers to attach to a runtime request for the given method and
   * request path: a Bearer WIMSE token plus a fresh DPoP proof bound to the
   * request (htu = base URL + path) and the token (ath).
   */
  async runtimeHeaders(method: string, path: string): Promise<Record<string, string>> {
    const token = await this.token();
    const proof = mintDPoPProofWithKeyStore(
      this.ks,
      this.agentId,
      this.publicKeyPem,
      method,
      this.baseUrl + path,
      token,
    );
    return { Authorization: `Bearer ${token}`, DPoP: proof };
  }

  /** Clears the cached token, forcing a fresh issuance on the next call. */
  invalidate(): void {
    this.cachedToken = '';
    this.expiresAtMs = 0;
  }
}

/**
 * Parses an RFC 3339 expiry to epoch ms; on failure falls back to a conservative
 * short window so the manager re-issues soon rather than trusting a bad value.
 */
function parseTokenExpiry(s: string): number {
  const ms = Date.parse(s);
  return Number.isNaN(ms) ? Date.now() + 5 * 60_000 : ms;
}

export class AgentTrustClient {
  private http: HttpClient;
  private authHttp: HttpClient;
  private auditHttp: HttpClient;
  public readonly agents: AgentsAPI;
  public readonly tokens: TokensAPI;
  public readonly actions: ActionsAPI;
  public readonly telemetry: TelemetryAPI;
  public readonly agentCards: AgentCardsAPI;
  public readonly a2a: A2AAPI;
  public readonly mcp: MCPAPI;
  public readonly delegations: DelegationsAPI;
  public readonly federation: FederationAPI;
  public readonly streaming: StreamingAPI;
  public readonly sessions: SessionsAPI;
  public readonly approvals: ApprovalsAPI;
  public readonly wimse: WIMSEAPI;

  constructor(options: AgentTrustClientOptions = {}) {
    const baseUrl = options.baseUrl || 'http://localhost:8080';
    const authUrl = options.authUrl || baseUrl.replace(':8081', ':8082');
    const auditUrl = options.auditUrl || baseUrl.replace(':8081', ':8084');
    const timeout = options.timeout || 30000;

    this.http = new HttpClient(baseUrl, timeout);

    this.authHttp = new HttpClient(authUrl, timeout);
    this.auditHttp = new HttpClient(auditUrl, timeout);

    if (options.apiKey) {
      this.http.setApiKey(options.apiKey);
      this.authHttp.setApiKey(options.apiKey);
      this.auditHttp.setApiKey(options.apiKey);
    }

    this.agents = new AgentsAPI(this.http);
    this.tokens = new TokensAPI(this.http, this.authHttp);
    this.actions = new ActionsAPI(this.authHttp);
    this.telemetry = new TelemetryAPI(this.auditHttp);
    this.agentCards = new AgentCardsAPI(this.http);
    this.a2a = new A2AAPI(this.http);
    this.mcp = new MCPAPI(this.http);
    this.delegations = new DelegationsAPI(this.http);
    this.federation = new FederationAPI(this.http);
    this.streaming = new StreamingAPI(this.http);
    this.sessions = new SessionsAPI(this.http);
    this.approvals = new ApprovalsAPI(this.http);
    this.wimse = new WIMSEAPI(this.http);
  }

  /** The configured gateway base URL (used as the DPoP `htu` origin). */
  getBaseUrl(): string {
    return this.http.getBaseUrl();
  }

  /**
   * Route runtime authorization checks (`actions.check`) through an agent's
   * WIMSE token plus a per-request DPoP proof, in addition to any org API key.
   */
  useAgentCredentials(ac: AgentCredentials): void {
    this.actions.setAgentCredentials(ac);
  }

  /**
   * Set org API key on all internal HTTP clients
   */
  setApiKey(apiKey: string): void {
    this.http.setApiKey(apiKey);
    this.authHttp.setApiKey(apiKey);
    this.auditHttp.setApiKey(apiKey);
  }

  /**
   * Check service health
   */
  async health(): Promise<HealthResponse> {
    return this.http.get<HealthResponse>('/health');
  }

  /**
   * Create client from environment variables.
   *
   * Env vars: AGENTTRUST_URL (or AGENTTRUST_BASE_URL),
   * AGENTTRUST_AUTH_URL, AGENTTRUST_AUDIT_URL, AGENTTRUST_API_KEY.
   */
  static fromEnv(): AgentTrustClient {
    const apiKey = process.env.AGENTTRUST_API_KEY;
    if (!apiKey) {
      console.warn(
        '[AgentTrust SDK] AGENTTRUST_API_KEY environment variable is not set. ' +
        'API calls will fail without authentication.'
      );
    }
    const baseUrl =
      process.env.AGENTTRUST_URL ||
      process.env.AGENTTRUST_BASE_URL ||
      'http://localhost:8080';

    return new AgentTrustClient({
      baseUrl,
      authUrl: process.env.AGENTTRUST_AUTH_URL,
      auditUrl: process.env.AGENTTRUST_AUDIT_URL,
      apiKey,
    });
  }
}
