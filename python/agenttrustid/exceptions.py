"""AgentTrust SDK Exceptions"""


class AgentTrustError(Exception):
    """Base exception for AgentTrust SDK errors"""

    def __init__(self, message: str, code: str = None, details: dict = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}


class AuthenticationError(AgentTrustError):
    """Raised when authentication fails (invalid or expired token)"""
    pass


class AuthorizationError(AgentTrustError):
    """Raised when authorization fails (insufficient scope, policy denied)"""
    pass


class TokenExpiredError(AgentTrustError):
    """Raised when a token has expired"""
    pass


class AgentRevokedError(AgentTrustError):
    """Raised when an agent or its tokens have been revoked"""
    pass


class NetworkError(AgentTrustError):
    """Raised when network communication fails"""
    pass


class ValidationError(AgentTrustError):
    """Raised when request validation fails"""
    pass
