package id.agenttrust.sdk.exceptions;

/**
 * Raised when a network-level failure occurs, such as connection refused,
 * timeout, or DNS resolution failure.
 */
public class NetworkException extends AgentTrustException {

    public NetworkException(String message) {
        super(message, "NETWORK_ERROR", 0);
    }

    public NetworkException(String message, Throwable cause) {
        super(message, "NETWORK_ERROR", 0, cause);
    }
}
