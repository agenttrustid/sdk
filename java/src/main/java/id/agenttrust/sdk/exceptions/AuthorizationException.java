package id.agenttrust.sdk.exceptions;

/**
 * Raised when authorization is denied (HTTP 403).
 * <p>
 * The caller does not have sufficient permissions for the requested operation.
 */
public class AuthorizationException extends AgentTrustException {

    public AuthorizationException(String message) {
        super(message, "AUTH_DENIED", 403);
    }

    public AuthorizationException(String message, Throwable cause) {
        super(message, "AUTH_DENIED", 403, cause);
    }
}
