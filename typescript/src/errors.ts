/**
 * AgentTrust SDK Exceptions
 */

export class AgentTrustError extends Error {
  public code: string;
  public details: Record<string, unknown>;

  constructor(message: string, code: string = 'AGENTTRUST_ERROR', details: Record<string, unknown> = {}) {
    super(message);
    this.name = 'AgentTrustError';
    this.code = code;
    this.details = details;
  }
}


export class AuthenticationError extends AgentTrustError {
  constructor(message: string = 'Authentication failed', details: Record<string, unknown> = {}) {
    super(message, 'AUTHENTICATION_ERROR', details);
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends AgentTrustError {
  constructor(message: string = 'Authorization denied', details: Record<string, unknown> = {}) {
    super(message, 'AUTHORIZATION_ERROR', details);
    this.name = 'AuthorizationError';
  }
}

export class TokenExpiredError extends AgentTrustError {
  constructor(message: string = 'Token has expired', details: Record<string, unknown> = {}) {
    super(message, 'TOKEN_EXPIRED', details);
    this.name = 'TokenExpiredError';
  }
}

export class AgentRevokedError extends AgentTrustError {
  constructor(message: string = 'Agent has been revoked', details: Record<string, unknown> = {}) {
    super(message, 'AGENT_REVOKED', details);
    this.name = 'AgentRevokedError';
  }
}

export class NetworkError extends AgentTrustError {
  constructor(message: string, details: Record<string, unknown> = {}) {
    super(message, 'NETWORK_ERROR', details);
    this.name = 'NetworkError';
  }
}

export class ValidationError extends AgentTrustError {
  constructor(message: string, details: Record<string, unknown> = {}) {
    super(message, 'VALIDATION_ERROR', details);
    this.name = 'ValidationError';
  }
}
