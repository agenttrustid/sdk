package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.models.A2ATask;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A2A API — Agent-to-Agent task dispatch via JSON-RPC 2.0.
 * <p>
 * Methods send JSON-RPC requests to {@code /a2a} and unwrap the
 * {@code result} or {@code error} field automatically.
 * <p>
 * Obtain an instance via {@link AgentTrustClient#a2a()}.
 */
public class A2AAPI {

    private final AgentTrustHttpClient httpClient;
    private final AtomicLong requestCounter = new AtomicLong(0);

    A2AAPI(AgentTrustHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Sends a task from one agent to another.
     *
     * @param sourceAgentId the agent initiating the task
     * @param targetAgentId the agent that should perform the task
     * @param message       the task message payload
     * @return the created task
     * @throws AgentTrustException if the dispatch fails or the JSON-RPC call returns an error
     */
    public A2ATask sendTask(String sourceAgentId, String targetAgentId,
                            Map<String, Object> message) throws AgentTrustException {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("source_agent_id", sourceAgentId);
        params.put("target_agent_id", targetAgentId);
        params.put("message", message != null ? message : new LinkedHashMap<>());

        Map<String, Object> result = jsonRpc("tasks/send", params);
        return A2ATask.fromJson(result);
    }

    /**
     * Retrieves the status and result of a task.
     *
     * @param taskId the task identifier
     * @return the task
     * @throws AgentTrustException if the lookup fails
     */
    public A2ATask getTask(String taskId) throws AgentTrustException {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("id", taskId);
        Map<String, Object> result = jsonRpc("tasks/get", params);
        return A2ATask.fromJson(result);
    }

    /**
     * Cancels a running task.
     *
     * @param taskId the task identifier
     * @return the task in its cancelled state
     * @throws AgentTrustException if the cancel fails
     */
    public A2ATask cancelTask(String taskId) throws AgentTrustException {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("id", taskId);
        Map<String, Object> result = jsonRpc("tasks/cancel", params);
        return A2ATask.fromJson(result);
    }

    /**
     * Sends a message to an agent using the A2A v1.0 {@code message/send} method.
     * <p>
     * Posts a JSON-RPC request to the per-agent endpoint
     * ({@code /a2a/agents/{agentId}}) with a single user text part, and parses
     * the returned v1.0 {@link A2ATask}.
     *
     * @param agentId   the target agent identifier
     * @param text      the message text
     * @param messageId a client-generated unique message identifier
     * @param taskId    an existing task to continue, or {@code null} to start a new task
     * @return the resulting task
     * @throws AgentTrustException if the dispatch fails or the JSON-RPC call returns an error
     */
    public A2ATask sendMessage(String agentId, String text, String messageId, String taskId)
            throws AgentTrustException {
        Map<String, Object> textPart = new LinkedHashMap<>();
        textPart.put("kind", "text");
        textPart.put("text", text);

        List<Object> parts = new ArrayList<>();
        parts.add(textPart);

        Map<String, Object> message = new LinkedHashMap<>();
        message.put("role", "user");
        message.put("parts", parts);
        message.put("messageId", messageId);
        if (taskId != null) {
            message.put("taskId", taskId);
        }

        Map<String, Object> params = new LinkedHashMap<>();
        params.put("message", message);

        Map<String, Object> result = jsonRpc("/a2a/agents/" + agentId, "message/send", params);
        return A2ATask.fromJson(result);
    }

    private Map<String, Object> jsonRpc(String method, Map<String, Object> params) throws AgentTrustException {
        return jsonRpc("/a2a", method, params);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> jsonRpc(String path, String method, Map<String, Object> params) throws AgentTrustException {
        long id = requestCounter.incrementAndGet();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("jsonrpc", "2.0");
        body.put("method", method);
        body.put("params", params);
        body.put("id", String.valueOf(id));

        Map<String, Object> response = httpClient.post(path, body);

        Object error = response.get("error");
        if (error instanceof Map) {
            Map<String, Object> errMap = (Map<String, Object>) error;
            String message = JsonUtil.getString(errMap, "message", "A2A RPC error");
            Object code = errMap.get("code");
            String codeStr = code != null ? code.toString() : "UNKNOWN";
            throw new AgentTrustException(message, "A2A_ERROR_" + codeStr, 200);
        }

        Object result = response.get("result");
        if (result instanceof Map) {
            return (Map<String, Object>) result;
        }
        return response;
    }
}
