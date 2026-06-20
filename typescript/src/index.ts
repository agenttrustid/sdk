/**
 * AgentTrust SDK — Authentication and authorization for AI agents.
 *
 * @example
 * ```typescript
 * import { AgentTrustClient } from '@agenttrustid/sdk';
 *
 * const client = new AgentTrustClient({ baseUrl: 'http://localhost:8080' });
 *
 * // Create an agent
 * const agent = await client.agents.create({
 *   name: 'my-agent',
 *   framework: 'langchain'
 * });
 *
 * // Issue an opaque agent token (prefix `at_`)
 * const token = await client.tokens.issue({
 *   agentId: agent.id,
 *   scopes: ['files:read'],
 *   target: 'mcp://filesystem'
 * });
 *
 * // Validate tokens (for tool providers) — calls
 * // POST /api/v1/agent-tokens/introspect on the platform.
 * const result = await client.tokens.introspect({
 *   token: incomingToken,
 *   target: 'mcp://my-tool'
 * });
 * if (result.active) { /* token is good *\/ }
 * ```
 *
 * Legacy ATI* names remain exported as aliases for back-compat and will be
 * removed in a future major release.
 */

export {
  AgentTrustClient,
  AgentTrustGuard,
  AgentsAPI,
  TokensAPI,
  ActionsAPI,
  TelemetryAPI,
  AgentCardsAPI,
  A2AAPI,
  MCPAPI,
  DelegationsAPI,
  FederationAPI,
  StreamingAPI,
  SessionsAPI,
  ApprovalsAPI,
  WIMSEAPI,
  primaryUrl,
  trustScore,
  TRUST_EXTENSION_URI,
} from './client';

export {
  AgentTrustError,
  AuthenticationError,
  AuthorizationError,
  TokenExpiredError,
  AgentRevokedError,
  NetworkError,
  ValidationError,
} from './errors';

// Client-side agent identity keys.
export {
  generateAgentKey,
  signWithPrivateKeyPem,
  MemoryKeyStore,
  KeychainKeyStore,
} from './keys';
export type { AgentKeyPair, KeyStore } from './keys';

// Optional integrations (peer deps — `@langchain/core` and `ai`).
export {
  AgentTrustLangChainHandler,
} from './callbacks/langchain';

export {
  withAgentTrust as withAgentTrustVercelAI,
  withATI as withATIVercelAI,
} from './integrations/vercel-ai';

export type {
  Agent,
  Token,
  IntrospectionResult,
  VerificationResult,
  CreateAgentRequest,
  IssueTokenRequest,
  IntrospectTokenRequest,
  VerifyTokenRequest,
  ActionCheckRequest,
  ActionCheckResult,
  TelemetryEvent,
  TelemetryReportRequest,
  AgentTrustGuardOptions,
  AgentTrustClientOptions,
  HealthResponse,
  AgentStatus,
  Framework,
  GuardTier,
  AgentCard,
  AgentCardProvider,
  AgentCardInterface,
  AgentCardExtension,
  AgentCardCapabilities,
  AgentCardSecurityScheme,
  AgentCardSkill,
  AgentCardSignature,
  A2ATask,
  A2ATaskStatus,
  A2AMessageTask,
  SendTaskRequest,
  SendMessageRequest,
  MCPServer,
  RegisterMCPServerRequest,
  Delegation,
  CreateDelegationRequest,
  Session,
  InitSessionRequest,
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
  PoPProof,
  WIMSETokenResponse,
  VerifyWIMSETokenRequest,
  VerifyWIMSETokenResponse,
  ChallengeResponse,
} from './types';
