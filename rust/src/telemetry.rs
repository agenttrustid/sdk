//! Telemetry reporting for agent behavior tracking.
//!
//! Telemetry events are used to build an audit trail of agent behavior,
//! including tool calls, durations, and error rates.
//!
//! # Example
//!
//! ```rust,no_run
//! use agenttrustid::{AgentTrustClient, TelemetryEvent};
//!
//! let client = AgentTrustClient::builder().build().unwrap();
//!
//! client.telemetry().report(
//!     "agent-123",
//!     "session-456",
//!     &[TelemetryEvent {
//!         event_type: "tool_end".to_string(),
//!         tool_name: "web_search".to_string(),
//!         duration_ms: 1200,
//!         success: true,
//!         error_type: None,
//!         timestamp: "2026-01-01T00:00:00Z".to_string(),
//!     }],
//! ).unwrap();
//! ```

use crate::client::AgentTrustClient;
use crate::error::Result;
use crate::models::{TelemetryEvent, TelemetryReportRequest};

/// Provides agent behavior telemetry reporting.
///
/// Obtained via [`AgentTrustClient::telemetry()`].
pub struct TelemetryAPI<'a> {
    pub(crate) client: &'a AgentTrustClient,
}

impl<'a> TelemetryAPI<'a> {
    /// Send a batch of telemetry events to the AgentTrust ID audit service.
    ///
    /// Events should include tool call start/end timestamps, durations, success
    /// status, and any error types. This data is used for audit trails and
    /// behavioral anomaly detection.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The agent that generated the events.
    /// * `session_id` - Session ID for event correlation.
    /// * `events` - Slice of telemetry events to report.
    pub fn report(
        &self,
        agent_id: &str,
        session_id: &str,
        events: &[TelemetryEvent],
    ) -> Result<()> {
        let body = TelemetryReportRequest {
            agent_id: agent_id.to_string(),
            session_id: session_id.to_string(),
            events: events.to_vec(),
        };
        self.client
            .request_no_response("POST", "/api/v1/telemetry/report", Some(&body))
    }
}
