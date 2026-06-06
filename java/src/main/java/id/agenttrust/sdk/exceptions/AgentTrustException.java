package id.agenttrust.sdk.exceptions;

/**
 * Base checked exception for all AgentTrust ID SDK errors.
 * <p>
 * Every exception carries a machine-readable {@link #getCode() code} and the
 * HTTP {@link #getStatus() status} from the API response (0 when the error is
 * not HTTP-related, e.g. a network timeout).
 */
public class AgentTrustException extends Exception {

    private final String code;
    private final int status;

    /**
     * Creates a new AgentTrust ID exception.
     *
     * @param message human-readable error description
     * @param code    machine-readable error code (e.g. "AUTH_FAILED")
     * @param status  HTTP status code, or 0 if not applicable
     */
    public AgentTrustException(String message, String code, int status) {
        super(message);
        this.code = code;
        this.status = status;
    }

    /**
     * Creates a new AgentTrust ID exception with a cause.
     *
     * @param message human-readable error description
     * @param code    machine-readable error code
     * @param status  HTTP status code, or 0 if not applicable
     * @param cause   underlying cause
     */
    public AgentTrustException(String message, String code, int status, Throwable cause) {
        super(message, cause);
        this.code = code;
        this.status = status;
    }

    /** Returns the machine-readable error code (e.g. "AUTH_FAILED", "NETWORK_ERROR"). */
    public String getCode() {
        return code;
    }

    /** Returns the HTTP status code from the API response, or 0 when not applicable. */
    public int getStatus() {
        return status;
    }

    @Override
    public String toString() {
        if (code != null && !code.isEmpty()) {
            return String.format("AgentTrustException[code=%s, status=%d]: %s", code, status, getMessage());
        }
        return String.format("AgentTrustException[status=%d]: %s", status, getMessage());
    }
}
