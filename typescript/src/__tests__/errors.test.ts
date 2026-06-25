import {
  AgentTrustError,
  AuthenticationError,
  AuthorizationError,
  TokenExpiredError,
  AgentRevokedError,
  NetworkError,
  ValidationError,
} from '../errors';

describe('error classes', () => {
  it('AgentTrustError carries an explicit code and details', () => {
    const e = new AgentTrustError('boom', 'X_CODE', { a: 1 });
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe('AgentTrustError');
    expect(e.code).toBe('X_CODE');
    expect(e.details).toEqual({ a: 1 });
  });

  it('AgentTrustError defaults code and details', () => {
    const e = new AgentTrustError('boom');
    expect(e.code).toBe('AGENTTRUST_ERROR');
    expect(e.details).toEqual({});
  });

  it.each([
    [AuthenticationError, 'AuthenticationError', 'AUTHENTICATION_ERROR', 'Authentication failed'],
    [AuthorizationError, 'AuthorizationError', 'AUTHORIZATION_ERROR', 'Authorization denied'],
    [TokenExpiredError, 'TokenExpiredError', 'TOKEN_EXPIRED', 'Token has expired'],
    [AgentRevokedError, 'AgentRevokedError', 'AGENT_REVOKED', 'Agent has been revoked'],
  ])('%p uses its default message and code', (Cls, name, code, msg) => {
    const e = new (Cls as new () => AgentTrustError)();
    expect(e).toBeInstanceOf(AgentTrustError);
    expect(e.name).toBe(name);
    expect(e.code).toBe(code);
    expect(e.message).toBe(msg);
  });

  it.each([
    [NetworkError, 'NetworkError', 'NETWORK_ERROR'],
    [ValidationError, 'ValidationError', 'VALIDATION_ERROR'],
  ])('%p sets its code and a custom message + details', (Cls, name, code) => {
    const e = new (Cls as new (m: string, d?: Record<string, unknown>) => AgentTrustError)('custom', { x: 1 });
    expect(e).toBeInstanceOf(AgentTrustError);
    expect(e.name).toBe(name);
    expect(e.code).toBe(code);
    expect(e.message).toBe('custom');
    expect(e.details).toEqual({ x: 1 });
  });

  it('NetworkError and ValidationError default details to an empty object', () => {
    expect(new NetworkError('x').details).toEqual({});
    expect(new ValidationError('y').details).toEqual({});
  });
});
