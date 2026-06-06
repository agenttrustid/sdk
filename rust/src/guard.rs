//! High-level guard for pre-flight action checks and telemetry.
//!
//! [`AgentTrustGuard`] wraps the action-check and telemetry APIs into a simple
//! check-then-report pattern for agents that do not use framework-specific
//! callbacks (e.g., raw OpenAI/Anthropic SDK usage).
//!
//! # Example
//!
//! ```rust,no_run
//! use agenttrustid::{AgentTrustClient, AgentTrustGuard};
//!
//! let client = AgentTrustClient::builder()
//!     .base_url("http://localhost:8080")
//!     .api_key("sk_live_xxx")
//!     .build()
//!     .unwrap();
//!
//! let guard = AgentTrustGuard::builder(client, "agent-123")
//!     .block_on_deny(true)
//!     .fail_open(false)
//!     .build();
//!
//! // Before each tool call
//! guard.check("web_search", "AI news").unwrap();
//!
//! // Execute the tool call...
//!
//! // After each tool call
//! guard.report("web_search", true, 1200);
//!
//! // Telemetry is automatically flushed when the guard is dropped.
//! // Or flush manually:
//! guard.flush().ok();
//! ```

use std::sync::Mutex;

use chrono::Utc;
use uuid::Uuid;

use crate::client::AgentTrustClient;
use crate::error::{AgentTrustError, Result};
use crate::models::{ActionCheckRequest, TelemetryEvent};

/// Number of buffered events that triggers an automatic flush.
const AUTO_FLUSH_SIZE: usize = 10;

/// High-level guard for pre-flight action checks and telemetry reporting.
///
/// The guard owns an [`AgentTrustClient`] and manages a session with buffered
/// telemetry events. Events are automatically flushed when the buffer reaches
/// 10 events or when the guard is dropped.
///
/// Thread-safe: all mutable state is protected by a [`Mutex`].
pub struct AgentTrustGuard {
    client: AgentTrustClient,
    agent_id: String,
    session_id: String,
    block_on_deny: bool,
    fail_open: bool,
    default_action_effect: Option<String>,
    buffer: Mutex<Vec<TelemetryEvent>>,
}

impl AgentTrustGuard {
    /// Create a new guard with default settings.
    ///
    /// Defaults:
    /// - `block_on_deny`: `true` (denied actions return errors)
    /// - `fail_open`: `false` (errors when Guardian is unreachable)
    /// - `session_id`: auto-generated UUID v4
    /// - `default_action_effect`: `None`
    pub fn new(client: AgentTrustClient, agent_id: &str) -> Self {
        Self {
            client,
            agent_id: agent_id.to_string(),
            session_id: Uuid::new_v4().to_string(),
            block_on_deny: true,
            fail_open: false,
            default_action_effect: None,
            buffer: Mutex::new(Vec::with_capacity(AUTO_FLUSH_SIZE)),
        }
    }

    /// Create a new [`AgentTrustGuardBuilder`] for configuring the guard.
    pub fn builder(client: AgentTrustClient, agent_id: &str) -> AgentTrustGuardBuilder {
        AgentTrustGuardBuilder {
            client,
            agent_id: agent_id.to_string(),
            session_id: None,
            block_on_deny: true,
            fail_open: false,
            default_action_effect: None,
        }
    }

    /// Get the session ID for this guard.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Get the agent ID for this guard.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Perform a pre-flight authorization check for a tool call.
    ///
    /// Uses the `default_action_effect` if one was configured via the builder.
    ///
    /// Returns `Ok(())` if the action is allowed.
    ///
    /// # Behavior
    ///
    /// - If the action requires **elevation** and `block_on_deny` is `true`,
    ///   returns [`AgentTrustError::ElevationRequired`].
    /// - If the action is **denied** and `block_on_deny` is `true`, returns
    ///   [`AgentTrustError::ActionDenied`].
    /// - If the action is **denied** and `block_on_deny` is `false`, returns
    ///   `Ok(())` (silent denial).
    /// - If the Guardian is **unreachable** and `fail_open` is `true`, returns
    ///   `Ok(())` (fail-open behavior).
    /// - If the Guardian is **unreachable** and `fail_open` is `false`, returns
    ///   [`AgentTrustError::GuardianUnavailable`].
    pub fn check(&self, tool_name: &str, input_summary: &str) -> Result<()> {
        self.do_check(
            tool_name,
            input_summary,
            self.default_action_effect.as_deref(),
        )
    }

    /// Perform a pre-flight authorization check with an explicit action effect.
    ///
    /// This is like [`check()`](Self::check) but allows specifying the action
    /// effect (e.g., "read", "write", "admin") per-call instead of relying on
    /// the default.
    pub fn check_with_effect(
        &self,
        tool_name: &str,
        input_summary: &str,
        action_effect: &str,
    ) -> Result<()> {
        self.do_check(tool_name, input_summary, Some(action_effect))
    }

    /// Internal check implementation shared by `check` and `check_with_effect`.
    fn do_check(
        &self,
        tool_name: &str,
        input_summary: &str,
        action_effect: Option<&str>,
    ) -> Result<()> {
        let req = ActionCheckRequest {
            agent_id: self.agent_id.clone(),
            action: "tool_call".to_string(),
            tool_name: tool_name.to_string(),
            tool_input_summary: input_summary.to_string(),
            session_id: self.session_id.clone(),
            action_effect: action_effect.map(|s| s.to_string()),
        };

        let result = self.client.actions().check(&req);

        match result {
            Ok(check) => {
                // Check for elevation requirement first
                if check.elevation_required == Some(true) {
                    if self.block_on_deny {
                        return Err(AgentTrustError::ElevationRequired {
                            message: format!("Tool '{}' requires elevated approval", tool_name,),
                            approval_id: check.approval_id.unwrap_or_default(),
                        });
                    }
                    // block_on_deny is false: silently allow
                    return Ok(());
                }

                if !check.allowed {
                    if self.block_on_deny {
                        return Err(AgentTrustError::ActionDenied {
                            message: format!(
                                "Tool '{}' denied: {}",
                                tool_name,
                                check
                                    .reason
                                    .unwrap_or_else(|| "no reason given".to_string())
                            ),
                            check_id: check.check_id,
                        });
                    }
                    // block_on_deny is false: silently allow
                }
                Ok(())
            }
            Err(AgentTrustError::Network(_)) => {
                if self.fail_open {
                    Ok(())
                } else {
                    Err(AgentTrustError::GuardianUnavailable {
                        message: "Guardian service is unreachable".to_string(),
                    })
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Record a tool call result as a telemetry event.
    ///
    /// Events are buffered in memory and automatically flushed when the buffer
    /// reaches 10 events. Call [`flush()`](Self::flush) to send remaining events.
    ///
    /// This method never returns an error; telemetry is best-effort.
    pub fn report(&self, tool_name: &str, success: bool, duration_ms: u64) {
        let event_type = if success { "tool_end" } else { "tool_error" };

        let event = TelemetryEvent {
            event_type: event_type.to_string(),
            tool_name: tool_name.to_string(),
            duration_ms,
            success,
            error_type: None,
            timestamp: Utc::now().to_rfc3339(),
        };

        let should_flush = {
            let mut buf = self.buffer.lock().unwrap();
            buf.push(event);
            buf.len() >= AUTO_FLUSH_SIZE
        };

        if should_flush {
            // Best-effort flush; errors are silently ignored.
            let _ = self.flush();
        }
    }

    /// Send all buffered telemetry events to the AgentTrust ID audit service.
    ///
    /// Safe to call concurrently. If the buffer is empty, returns `Ok(())`
    /// immediately.
    pub fn flush(&self) -> Result<()> {
        let events = {
            let mut buf = self.buffer.lock().unwrap();
            if buf.is_empty() {
                return Ok(());
            }
            let events = buf.clone();
            buf.clear();
            events
        };

        self.client
            .telemetry()
            .report(&self.agent_id, &self.session_id, &events)
    }
}

impl Drop for AgentTrustGuard {
    /// Automatically flush remaining telemetry events when the guard is dropped.
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// Builder for configuring an [`AgentTrustGuard`].
pub struct AgentTrustGuardBuilder {
    client: AgentTrustClient,
    agent_id: String,
    session_id: Option<String>,
    block_on_deny: bool,
    fail_open: bool,
    default_action_effect: Option<String>,
}

impl AgentTrustGuardBuilder {
    /// Set a custom session ID.
    ///
    /// If not set, a random UUID v4 is generated.
    pub fn session_id(mut self, id: &str) -> Self {
        self.session_id = Some(id.to_string());
        self
    }

    /// Control whether [`AgentTrustGuard::check()`] returns an error when an action is denied.
    ///
    /// Default: `true`.
    pub fn block_on_deny(mut self, block: bool) -> Self {
        self.block_on_deny = block;
        self
    }

    /// Control behavior when the Guardian service is unreachable.
    ///
    /// If `true`, actions are allowed when the service is down (fail-open).
    /// If `false` (default), an error is returned.
    pub fn fail_open(mut self, open: bool) -> Self {
        self.fail_open = open;
        self
    }

    /// Set a default action effect (e.g., "read", "write", "admin") to include
    /// in all action checks performed by this guard.
    ///
    /// If not set, the `action_effect` field is omitted from check requests
    /// unless explicitly provided via [`AgentTrustGuard::check_with_effect()`].
    pub fn action_effect(mut self, effect: &str) -> Self {
        self.default_action_effect = Some(effect.to_string());
        self
    }

    /// Build the [`AgentTrustGuard`].
    pub fn build(self) -> AgentTrustGuard {
        AgentTrustGuard {
            client: self.client,
            agent_id: self.agent_id,
            session_id: self
                .session_id
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
            block_on_deny: self.block_on_deny,
            fail_open: self.fail_open,
            default_action_effect: self.default_action_effect,
            buffer: Mutex::new(Vec::with_capacity(AUTO_FLUSH_SIZE)),
        }
    }
}
