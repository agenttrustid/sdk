package id.agenttrust.sdk.exceptions;

/**
 * Raised when the requested resource is not found (HTTP 404).
 */
public class NotFoundException extends AgentTrustException {

    public NotFoundException(String message) {
        super(message, "NOT_FOUND", 404);
    }

    public NotFoundException(String message, Throwable cause) {
        super(message, "NOT_FOUND", 404, cause);
    }
}
