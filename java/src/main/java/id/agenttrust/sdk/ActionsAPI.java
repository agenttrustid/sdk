package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.models.ActionCheckResult;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Pre-flight action authorization checks.
 * <p>
 * Use this API to check whether an action is authorized before executing it.
 * Each check is a lightweight Fast Guard call (typically under 15ms).
 * <p>
 * Obtain an instance via {@link AgentTrustClient#actions()}.
 */
public class ActionsAPI {

    private final AgentTrustHttpClient httpClient;

    ActionsAPI(AgentTrustHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Checks if an action is authorized before executing it.
     *
     * @param request the action check parameters
     * @return the check result
     * @throws AgentTrustException if the request fails
     */
    public ActionCheckResult check(ActionCheckRequest request) throws AgentTrustException {
        Map<String, Object> body = request.toJson();
        Map<String, Object> result = httpClient.post("/api/v1/agenttrust/check", body);
        return ActionCheckResult.fromJson(result);
    }

    /**
     * Parameters for a pre-flight action check.
     */
    public static class ActionCheckRequest {

        private final String agentId;
        private final String action;
        private final String toolName;
        private final String toolInputSummary;
        private final String sessionId;
        private final String actionEffect;

        private ActionCheckRequest(Builder builder) {
            this.agentId = builder.agentId;
            this.action = builder.action;
            this.toolName = builder.toolName;
            // Truncate input summary to 200 chars for privacy
            String summary = builder.toolInputSummary != null ? builder.toolInputSummary : "";
            this.toolInputSummary = summary.length() > 200 ? summary.substring(0, 200) : summary;
            this.sessionId = builder.sessionId;
            this.actionEffect = builder.actionEffect;
        }

        Map<String, Object> toJson() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("agent_id", agentId);
            String actionName = toolName != null && !toolName.isEmpty() ? toolName : action;
            map.put("action_name", actionName);
            map.put("action_source", "api");
            map.put("action_input_summary", toolInputSummary);
            if (sessionId != null && !sessionId.isEmpty()) {
                map.put("session_id", sessionId);
            }
            if (actionEffect != null && !actionEffect.isEmpty()) {
                map.put("action_effect", actionEffect);
            }
            return map;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static class Builder {
            private String agentId;
            private String action = "tool_call";
            private String toolName = "";
            private String toolInputSummary = "";
            private String sessionId;
            private String actionEffect;

            private Builder() {
            }

            public Builder agentId(String agentId) {
                this.agentId = agentId;
                return this;
            }

            public Builder action(String action) {
                this.action = action;
                return this;
            }

            public Builder toolName(String toolName) {
                this.toolName = toolName;
                return this;
            }

            public Builder toolInputSummary(String toolInputSummary) {
                this.toolInputSummary = toolInputSummary;
                return this;
            }

            public Builder sessionId(String sessionId) {
                this.sessionId = sessionId;
                return this;
            }

            public Builder actionEffect(String actionEffect) {
                this.actionEffect = actionEffect;
                return this;
            }

            public ActionCheckRequest build() {
                if (agentId == null || agentId.isEmpty()) {
                    throw new IllegalArgumentException("agentId is required");
                }
                return new ActionCheckRequest(this);
            }
        }
    }
}
