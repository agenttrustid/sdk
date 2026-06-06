package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.models.ApprovalRequest;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Approval management API for elevated actions.
 * <p>
 * Provides methods to approve, deny, and retrieve approval requests
 * created when actions require elevation.
 * Obtain an instance via {@link AgentTrustClient#approvals()}.
 */
public class ApprovalsAPI {

    private final AgentTrustHttpClient httpClient;

    ApprovalsAPI(AgentTrustHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Approves an elevated action request.
     *
     * @param approvalId the approval request identifier
     * @param decidedBy  who is approving the request
     * @throws AgentTrustException if the request fails
     */
    public void approve(String approvalId, String decidedBy) throws AgentTrustException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("decided_by", decidedBy);
        httpClient.post("/mcp/approvals/" + approvalId + "/approve", body);
    }

    /**
     * Denies an elevated action request.
     *
     * @param approvalId the approval request identifier
     * @param decidedBy  who is denying the request
     * @throws AgentTrustException if the request fails
     */
    public void deny(String approvalId, String decidedBy) throws AgentTrustException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("decided_by", decidedBy);
        httpClient.post("/mcp/approvals/" + approvalId + "/deny", body);
    }

    /**
     * Gets an approval request by ID.
     *
     * @param approvalId the approval request identifier
     * @return the approval request
     * @throws AgentTrustException if the approval request is not found or the request fails
     */
    public ApprovalRequest get(String approvalId) throws AgentTrustException {
        Map<String, Object> result = httpClient.get("/mcp/approvals/" + approvalId);
        return ApprovalRequest.fromMap(result);
    }
}
