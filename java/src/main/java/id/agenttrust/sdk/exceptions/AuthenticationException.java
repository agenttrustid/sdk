package id.agenttrust.sdk.exceptions;

/**
 * Raised when authentication fails (HTTP 401).
 * <p>
 * This typically means the API key is invalid, missing, or expired.
 */
public class AuthenticationException extends AgentTrustException {

    public AuthenticationException(String message) {
        super(message, "AUTH_FAILED", 401);
    }

    public AuthenticationException(String message, Throwable cause) {
        super(message, "AUTH_FAILED", 401, cause);
    }
}
