package id.agenttrust.sdk.exceptions;

/**
 * Raised when an action requires elevated approval before it can proceed.
 * <p>
 * The {@link #getApprovalId()} returns the ID of the pending approval request
 * that must be approved (via {@code ApprovalsAPI.approve()}) before retrying
 * the action.
 */
public class ElevationRequiredException extends AgentTrustException {

    private final String approvalId;

    /**
     * Creates a new elevation required exception.
     *
     * @param message    human-readable description
     * @param approvalId the pending approval request ID
     */
    public ElevationRequiredException(String message, String approvalId) {
        super(message, "ELEVATION_REQUIRED", 0);
        this.approvalId = approvalId;
    }

    /**
     * Returns the approval request ID that must be approved before
     * the action can proceed.
     */
    public String getApprovalId() {
        return approvalId;
    }
}
