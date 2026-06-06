package id.agenttrust.sdk.exceptions;

/**
 * Raised when request validation fails (HTTP 400).
 * <p>
 * Check the error message for details about which fields are invalid.
 */
public class ValidationException extends AgentTrustException {

    public ValidationException(String message) {
        super(message, "VALIDATION_ERROR", 400);
    }

    public ValidationException(String message, Throwable cause) {
        super(message, "VALIDATION_ERROR", 400, cause);
    }
}
