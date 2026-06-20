/**
 * AgentTrust ID SDK Types
 */

export type AgentStatus = 'active' | 'suspended' | 'revoked';
export type Framework = 'openai' | 'anthropic' | 'langchain' | 'crewai' | 'autogen' | 'custom';
export type GuardTier = 'fast' | 'spot' | 'deep';

export interface Agent {
  id: string;
  name: string;
  orgId: string;
  framework: Framework;
  publicKey: string;
  status: AgentStatus;
  capabilities: string[];
  metadata: Record<string, unknown>;
  createdAt?: Date;
  privateKey?: string;
}

/**
 * An opaque agent token.
 *
 * Tokens are random strings prefixed with `at_` (e.g. `at_xK3z9...`). They
 * are NOT JWTs — they have no signature and cannot be validated client-side.
 * To check a token, call `client.tokens.introspect(token)`.
 */
export interface Token {
  /** The opaque token string (e.g. `at_xK3z9...`). */
  token: string;
  agentId: string;
  scopes: string[];
  audience: string[];
  issuedAt: Date;
  expiresAt: Date;
  tokenId?: string;
}

/**
 * Result of `POST /api/v1/agent-tokens/introspect`.
 */
export interface IntrospectionResult {
  active: boolean;
  agentId?: string;
  orgId?: string;
  scopes: string[];
  expiresAt?: Date;
  reasoning?: string;
  guardTier?: GuardTier;
  confidence?: number;
  latencyMs?: number;
}

/** @deprecated Use {@link IntrospectionResult}. */
export type VerificationResult = IntrospectionResult;

export interface CreateAgentRequest {
  name: string;
  framework?: Framework;
  orgId?: string;
  capabilities?: string[];
  metadata?: Record<string, unknown>;
  /**
   * Optional caller-supplied Ed25519 public key (PKIX PEM). When omitted, the
   * SDK generates a keypair client-side and sends only the public key; the
   * private key stays on this machine.
   */
  publicKey?: string;
}

export interface IssueTokenRequest {
  agentId: string;
  scopes: string[];
  target?: string;
  ttlSeconds?: number;
  sessionId?: string;
}

/**
 * Request body for `POST /api/v1/agent-tokens/introspect`.
 */
export interface IntrospectTokenRequest {
  token: string;
  target?: string;
  requiredScopes?: string[];
}

/** @deprecated Use {@link IntrospectTokenRequest}. */
export type VerifyTokenRequest = IntrospectTokenRequest;

export interface ActionCheckRequest {
  agentId: string;
  action?: string;
  toolName: string;
  toolInputSummary?: string;
  sessionId?: string;
  actionEffect?: string;
}

export interface ActionCheckResult {
  allowed: boolean;
  checkId?: string;
  confidence?: number;
  guardTier?: GuardTier;
  latencyMs?: number;
  reason?: string;
  elevationRequired?: boolean;
  approvalId?: string;
}

export interface TelemetryEvent {
  event_type: string;
  tool_name: string;
  duration_ms?: number;
  success?: boolean;
  error_type?: string;
  timestamp?: string;
}

export interface TelemetryReportRequest {
  agentId: string;
  sessionId: string;
  events: TelemetryEvent[];
}

export interface AgentTrustGuardOptions {
  blockOnDeny?: boolean;
  failOpen?: boolean;
  sessionId?: string;
}

export interface AgentTrustClientOptions {
  baseUrl?: string;
  authUrl?: string;
  auditUrl?: string;
  apiKey?: string;
  timeout?: number;
}

export interface HealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  service?: string;
  version?: string;
}

// --- Agent Cards ---

export interface AgentCardProvider {
  organization: string;
  url?: string;
}

/** A2A v1.0 transport interface descriptor. */
export interface AgentCardInterface {
  url: string;
  protocolBinding: string;
  protocolVersion: string;
  tenant?: string;
}

/** A2A v1.0 capability extension (e.g. the AgentTrust trust extension). */
export interface AgentCardExtension {
  uri: string;
  description?: string;
  required?: boolean;
  params?: Record<string, unknown>;
}

export interface AgentCardCapabilities {
  streaming: boolean;
  pushNotifications: boolean;
  extensions?: AgentCardExtension[];
  extendedAgentCard?: boolean;
}

/** A2A v1.0 security scheme (OpenAPI-style). */
export interface AgentCardSecurityScheme {
  type: string;
  scheme?: string;
}

export interface AgentCardSkill {
  id: string;
  name: string;
  description: string;
  tags: string[];
  examples?: string[];
  inputModes?: string[];
  outputModes?: string[];
}

/** A2A v1.0 detached JWS signature over the card. */
export interface AgentCardSignature {
  protected: string;
  signature: string;
  header?: Record<string, unknown>;
}

/**
 * A2A v1.0 Agent Card.
 *
 * Every field added in v1.0 is optional so that older cached cards (which may
 * only carry the legacy top-level `url`) still parse without throwing.
 */
export interface AgentCard {
  name: string;
  description?: string;
  version: string;
  supportedInterfaces?: AgentCardInterface[];
  provider?: AgentCardProvider;
  capabilities: AgentCardCapabilities;
  securitySchemes?: Record<string, AgentCardSecurityScheme>;
  securityRequirements?: Record<string, string[]>[];
  defaultInputModes?: string[];
  defaultOutputModes?: string[];
  skills: AgentCardSkill[];
  signatures?: AgentCardSignature[];
  documentationUrl?: string;
  iconUrl?: string;
  /** Legacy top-level URL retained for backward compatibility with cached cards. */
  url?: string;
}

// --- A2A Tasks ---

export interface A2ATask {
  id: string;
  sourceAgentId?: string;
  targetAgentId?: string;
  status: string;
  message?: Record<string, unknown>;
  artifacts?: unknown[];
  metadata?: Record<string, unknown>;
  createdAt?: string;
  updatedAt?: string;
}

export interface SendTaskRequest {
  sourceAgentId: string;
  targetAgentId: string;
  message: Record<string, unknown>;
}

// --- A2A v1.0 message/send ---

/** A2A v1.0 Task status. */
export interface A2ATaskStatus {
  state: string;
  timestamp?: string;
}

/** A2A v1.0 Task returned by the `message/send` method. */
export interface A2AMessageTask {
  id: string;
  contextId?: string;
  status: A2ATaskStatus;
  history?: Record<string, unknown>[];
  artifacts?: unknown[];
}

export interface SendMessageRequest {
  text: string;
  messageId?: string;
  taskId?: string;
}

// --- MCP ---

export interface MCPServer {
  id: string;
  name: string;
  url: string;
  capabilities?: string[];
  orgId?: string;
  createdAt?: string;
}

export interface RegisterMCPServerRequest {
  name: string;
  url: string;
  capabilities?: string[];
}

// --- Delegations ---

export interface Delegation {
  id: string;
  fromAgentId: string;
  toAgentId: string;
  orgId?: string;
  scope: string[];
  restrictions?: Record<string, unknown>;
  delegationChain?: string[];
  expiresAt: string;
  revokedAt?: string;
  createdAt: string;
}

export interface CreateDelegationRequest {
  fromAgentId: string;
  toAgentId: string;
  scope: string[];
  ttlSeconds?: number;
  restrictions?: Record<string, unknown>;
  parentDelegationId?: string;
}

// --- Sessions ---

export interface Session {
  sessionId: string;
  agentId: string;
  orgId: string;
  source: string;
  serverId?: string;
  delegationId?: string;
  providerId?: string;
  issuer?: string;
  trustLevel?: string;
  mode: string;
  allowedActions: string[];
  scopeCeiling: string[];
  totalCalls: number;
  readCalls: number;
  writeCalls: number;
  deniedCalls: number;
  createdAt?: string;
  lastActivityAt?: string;
}

export interface InitSessionRequest {
  agentId: string;
  serverId: string;
}

export interface InitAPISessionRequest {
  token: string;
}

// --- Federation ---

export interface FederationProvider {
  id: string;
  orgId: string;
  issuer: string;
  name: string;
  jwksUri: string;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  trustLevel: string;
  status: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface RegisterFederationProviderRequest {
  issuer: string;
  name: string;
  trustLevel?: string;
}

export interface VerifyFederatedTokenRequest {
  token: string;
  issuerHint?: string;
}

export interface VerifyFederatedTokenResult {
  valid: boolean;
  agentId?: string;
  issuer?: string;
  expiresAt?: string;
  error?: string;
}

export interface IssueFederatedIDTokenRequest {
  audience?: string;
  nonce?: string;
  scopes?: string[];
  ttl?: number;
}

export interface IssueFederatedIDTokenResult {
  idToken: string;
  token?: string;
  expiresIn: number;
  expiresAt?: string;
}

// --- SIEM Streaming ---

export interface SIEMDestination {
  id: string;
  orgId?: string;
  name: string;
  destinationType: string;
  endpointUrl: string;
  authToken?: string;
  isActive: boolean;
  batchSize: number;
  flushIntervalSeconds: number;
  filterEventTypes?: string[];
  createdAt?: string;
  updatedAt?: string;
}

export interface CreateSIEMDestinationRequest {
  name: string;
  destinationType: string;
  endpointUrl: string;
  authToken?: string;
  batchSize?: number;
  flushIntervalSeconds?: number;
  filterEventTypes?: string[];
}

export interface UpdateSIEMDestinationRequest {
  name?: string;
  endpointUrl?: string;
  authToken?: string;
  isActive?: boolean;
  batchSize?: number;
  flushIntervalSeconds?: number;
  filterEventTypes?: string[];
}

export interface SIEMDeliveryRecord {
  id: string;
  destinationId: string;
  batchSize: number;
  status: string;
  statusCode?: number;
  errorMessage?: string;
  deliveredAt: string;
}

// --- Approvals ---

export interface ApprovalRequest {
  id: string;
  sessionId: string;
  agentId: string;
  orgId: string;
  actionName: string;
  actionEffect: string;
  status: string;
  createdAt?: string;
  expiresAt?: string;
  decidedBy?: string;
}

// Legacy type aliases.
