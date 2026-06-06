package id.agenttrust.sdk;

import id.agenttrust.sdk.exceptions.AgentTrustException;
import id.agenttrust.sdk.exceptions.ElevationRequiredException;
import id.agenttrust.sdk.exceptions.NetworkException;
import id.agenttrust.sdk.models.ActionCheckResult;
import id.agenttrust.sdk.models.TelemetryEvent;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * High-level guard that combines pre-flight action checks with buffered
 * telemetry reporting.
 * <p>
 * {@code AgentTrustGuard} is designed for agents that use raw OpenAI/Anthropic SDKs
 * rather than framework-specific callbacks. It is thread-safe and buffers
 * telemetry events, automatically flushing when the buffer reaches 10 events.
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * try (AgentTrustGuard guard = new AgentTrustGuard(client, "agent-123")) {
 *     // Before each tool call
 *     guard.check("web_search", "AI news");
 *
 *     // Execute the tool call...
 *
 *     // After each tool call
 *     guard.report("web_search", true, 1200);
 * }
 * }</pre>
 */
public class AgentTrustGuard implements AutoCloseable {

    private static final Logger logger = Logger.getLogger(AgentTrustGuard.class.getName());
    private static final int AUTO_FLUSH_SIZE = 10;

    private final AgentTrustClient client;
    private final String agentId;
    private final String sessionId;
    private final boolean blockOnDeny;
    private final boolean failOpen;

    private final Object lock = new Object();
    private final List<TelemetryEvent> buffer = new ArrayList<>();

    /**
     * Creates a guard with default options (blockOnDeny=true, failOpen=false,
     * auto-generated sessionId).
     *
     * @param client  AgentTrust ID client instance
     * @param agentId registered agent ID
     */
    public AgentTrustGuard(AgentTrustClient client, String agentId) {
        this(client, agentId, new Options());
    }

    /**
     * Creates a guard with custom options.
     *
     * @param client  AgentTrust ID client instance
     * @param agentId registered agent ID
     * @param options guard configuration
     */
    public AgentTrustGuard(AgentTrustClient client, String agentId, Options options) {
        this.client = client;
        this.agentId = agentId;
        this.sessionId = (options.sessionId != null && !options.sessionId.isEmpty())
                ? options.sessionId : UUID.randomUUID().toString();
        this.blockOnDeny = options.blockOnDeny;
        this.failOpen = options.failOpen;
    }

    /**
     * Performs a pre-flight authorization check before a tool call.
     * <p>
     * If the action is denied and {@code blockOnDeny} is true, an
     * {@link AgentTrustException} with code "ACTION_DENIED" is thrown.
     * <p>
     * If the Guardian service is unreachable and {@code failOpen} is false,
     * an {@link AgentTrustException} with code "GUARDIAN_UNAVAILABLE" is thrown.
     *
     * @param toolName     name of the tool being called
     * @param inputSummary truncated summary of the tool input (max 200 chars)
     * @throws AgentTrustException if the action is denied or the Guardian is unreachable
     */
    public void check(String toolName, String inputSummary) throws AgentTrustException {
        check(toolName, inputSummary, null);
    }

    /**
     * Performs a pre-flight authorization check before a tool call, with an
     * optional action effect.
     * <p>
     * If the action is denied and {@code blockOnDeny} is true, an
     * {@link AgentTrustException} with code "ACTION_DENIED" is thrown.
     * <p>
     * If the result indicates elevation is required and {@code blockOnDeny}
     * is true, an {@link ElevationRequiredException} is thrown containing
     * the approval ID.
     * <p>
     * If the Guardian service is unreachable and {@code failOpen} is false,
     * an {@link AgentTrustException} with code "GUARDIAN_UNAVAILABLE" is thrown.
     *
     * @param toolName     name of the tool being called
     * @param inputSummary truncated summary of the tool input (max 200 chars)
     * @param actionEffect the action effect (e.g. "read", "write", "admin"), or null
     * @throws AgentTrustException                if the action is denied or the Guardian is unreachable
     * @throws ElevationRequiredException  if the action requires elevated approval
     */
    public void check(String toolName, String inputSummary, String actionEffect) throws AgentTrustException {
        try {
            ActionsAPI.ActionCheckRequest.Builder reqBuilder = ActionsAPI.ActionCheckRequest.builder()
                    .agentId(agentId)
                    .action("tool_call")
                    .toolName(toolName)
                    .toolInputSummary(inputSummary != null ? inputSummary : "")
                    .sessionId(sessionId);

            if (actionEffect != null && !actionEffect.isEmpty()) {
                reqBuilder.actionEffect(actionEffect);
            }

            ActionCheckResult result = client.actions().check(reqBuilder.build());

            // Handle elevation required
            if (result.isElevationRequired()) {
                logger.warning("AgentTrust ID elevation required: tool=" + toolName +
                        " approvalId=" + result.getApprovalId());
                if (blockOnDeny) {
                    throw new ElevationRequiredException(
                            "Tool '" + toolName + "' requires elevated approval",
                            result.getApprovalId());
                }
                return;
            }

            if (!result.isAllowed()) {
                logger.warning("AgentTrust ID denied: tool=" + toolName + " reason=" + result.getReason());
                if (blockOnDeny) {
                    throw new AgentTrustException(
                            "Tool '" + toolName + "' denied: " + result.getReason(),
                            "ACTION_DENIED", 0);
                }
            }
        } catch (AgentTrustException e) {
            // Re-throw AgentTrust ID exceptions directly (includes ACTION_DENIED and ELEVATION_REQUIRED)
            if ("ACTION_DENIED".equals(e.getCode()) || "ELEVATION_REQUIRED".equals(e.getCode())) {
                throw e;
            }
            // Network errors respect failOpen setting
            if (e instanceof NetworkException) {
                if (failOpen) {
                    logger.info("Guardian unreachable, fail-open enabled, allowing action");
                    return;
                }
                throw new AgentTrustException(
                        "Guardian unreachable: " + e.getMessage(),
                        "GUARDIAN_UNAVAILABLE", 0, e);
            }
            throw e;
        }
    }

    /**
     * Records a tool call result as a telemetry event.
     * <p>
     * Events are buffered in memory and automatically flushed when the buffer
     * reaches 10 events. Call {@link #flush()} or {@link #close()} to send
     * remaining events.
     * <p>
     * This method never throws; telemetry is best-effort.
     *
     * @param toolName   name of the tool
     * @param success    whether the tool call succeeded
     * @param durationMs how long the tool call took in milliseconds
     */
    public void report(String toolName, boolean success, int durationMs) {
        String eventType = success ? "tool_end" : "tool_error";
        TelemetryEvent event = new TelemetryEvent(
                eventType, toolName, durationMs, success, null, Instant.now().toString()
        );

        boolean shouldFlush = false;
        synchronized (lock) {
            buffer.add(event);
            if (buffer.size() >= AUTO_FLUSH_SIZE) {
                shouldFlush = true;
            }
        }

        if (shouldFlush) {
            try {
                flush();
            } catch (AgentTrustException e) {
                logger.log(Level.WARNING, "Auto-flush failed", e);
            }
        }
    }

    /**
     * Sends all buffered telemetry events to the AgentTrust ID audit service.
     * <p>
     * Safe to call concurrently. If the buffer is empty, this returns
     * immediately.
     *
     * @throws AgentTrustException if the telemetry report fails
     */
    public void flush() throws AgentTrustException {
        List<TelemetryEvent> events;
        synchronized (lock) {
            if (buffer.isEmpty()) {
                return;
            }
            events = new ArrayList<>(buffer);
            buffer.clear();
        }
        client.telemetry().report(agentId, sessionId, events);
    }

    /**
     * Flushes any remaining telemetry events and releases resources.
     * <p>
     * Always call this (or use try-with-resources) when the guard is no longer
     * needed.
     *
     * @throws AgentTrustException if the final flush fails
     */
    @Override
    public void close() throws AgentTrustException {
        flush();
    }

    /** Returns the session ID used by this guard. */
    public String getSessionId() {
        return sessionId;
    }

    // ------------------------------------------------------------------
    // Options
    // ------------------------------------------------------------------

    /**
     * Configuration options for {@link AgentTrustGuard}.
     */
    public static class Options {
        /**
         * If true, {@link AgentTrustGuard#check} throws an exception when the action
         * is denied. Default: true.
         */
        public boolean blockOnDeny = true;

        /**
         * If true, actions are allowed when the Guardian service is unreachable.
         * Default: false.
         */
        public boolean failOpen = false;

        /**
         * Session ID for event correlation. If null or empty, a UUID is
         * generated automatically.
         */
        public String sessionId;
    }
}
