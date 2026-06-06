//! SIEM streaming destination management and event subscription.
//!
//! Use this API to register external SIEM destinations (Splunk, Datadog, etc.)
//! that AgentTrust ID will stream audit events to, and to inspect their delivery logs.
//!
//! For agent-side consumption of streamed events, [`Streaming::subscribe`]
//! offers a polling helper that calls a handler for each new delivery record.
//!
//! # Example
//!
//! ```rust,no_run
//! use agenttrustid::{AgentTrustClient, CreateSIEMDestinationRequest};
//!
//! let client = AgentTrustClient::builder().build().unwrap();
//!
//! let dest = client.streaming().create(&CreateSIEMDestinationRequest {
//!     name: "splunk-prod".to_string(),
//!     destination_type: "splunk".to_string(),
//!     endpoint_url: "https://siem.example.com".to_string(),
//!     auth_token: Some("token".to_string()),
//!     batch_size: Some(100),
//!     flush_interval_seconds: Some(30),
//!     filter_event_types: None,
//! }).unwrap();
//!
//! println!("destination: {}", dest.id);
//! ```

use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

use crate::client::AgentTrustClient;
use crate::error::Result;
use crate::models::{
    CreateSIEMDestinationRequest, SIEMDeliveryRecord, SIEMDestination, UpdateSIEMDestinationRequest,
};

/// Provides SIEM streaming destination management.
///
/// Obtained via [`AgentTrustClient::streaming()`].
pub struct Streaming<'a> {
    pub(crate) client: &'a AgentTrustClient,
}

#[derive(Debug, Deserialize)]
struct DestinationListResponse {
    #[serde(default)]
    destinations: Option<Vec<SIEMDestination>>,
}

#[derive(Debug, Deserialize)]
struct DeliveryLogResponse {
    #[serde(default)]
    logs: Option<Vec<SIEMDeliveryRecord>>,
}

/// Filter options for [`Streaming::subscribe`].
///
/// Currently filters by destination ID; additional filters may be added in
/// later versions.
#[derive(Debug, Clone, Default)]
pub struct StreamFilter {
    /// Required destination ID to subscribe to.
    pub destination_id: String,
    /// Polling interval. Defaults to 5 seconds when zero.
    pub poll_interval: Option<Duration>,
    /// Maximum polls before returning. `None` polls forever (use carefully).
    pub max_polls: Option<u32>,
}

impl<'a> Streaming<'a> {
    /// Create a new SIEM destination.
    ///
    /// Calls `POST /api/v1/siem/destinations`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::{AgentTrustClient, CreateSIEMDestinationRequest};
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let d = client.streaming().create(&CreateSIEMDestinationRequest {
    ///     name: "splunk".into(),
    ///     destination_type: "splunk".into(),
    ///     endpoint_url: "https://x".into(),
    ///     auth_token: None,
    ///     batch_size: None,
    ///     flush_interval_seconds: None,
    ///     filter_event_types: None,
    /// }).unwrap();
    /// assert!(!d.id.is_empty());
    /// ```
    pub fn create(&self, req: &CreateSIEMDestinationRequest) -> Result<SIEMDestination> {
        self.client
            .request("POST", "/api/v1/siem/destinations", Some(req))
    }

    /// List SIEM destinations.
    ///
    /// Calls `GET /api/v1/siem/destinations`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let list = client.streaming().list().unwrap();
    /// println!("{} destinations", list.len());
    /// ```
    pub fn list(&self) -> Result<Vec<SIEMDestination>> {
        let value: Value = self
            .client
            .request("GET", "/api/v1/siem/destinations", None::<&()>)?;
        if let Value::Array(_) = &value {
            let v: Vec<SIEMDestination> = serde_json::from_value(value)?;
            return Ok(v);
        }
        let resp: DestinationListResponse = serde_json::from_value(value)?;
        Ok(resp.destinations.unwrap_or_default())
    }

    /// Retrieve a SIEM destination by ID.
    ///
    /// Calls `GET /api/v1/siem/destinations/{id}`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let d = client.streaming().get("dest-1").unwrap();
    /// println!("active: {}", d.is_active);
    /// ```
    pub fn get(&self, destination_id: &str) -> Result<SIEMDestination> {
        let path = format!("/api/v1/siem/destinations/{}", destination_id);
        self.client.request("GET", &path, None::<&()>)
    }

    /// Update a SIEM destination.
    ///
    /// Calls `PUT /api/v1/siem/destinations/{id}`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::{AgentTrustClient, UpdateSIEMDestinationRequest};
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let mut req = UpdateSIEMDestinationRequest::default();
    /// req.is_active = Some(false);
    /// let d = client.streaming().update("dest-1", &req).unwrap();
    /// assert!(!d.is_active);
    /// ```
    pub fn update(
        &self,
        destination_id: &str,
        req: &UpdateSIEMDestinationRequest,
    ) -> Result<SIEMDestination> {
        let path = format!("/api/v1/siem/destinations/{}", destination_id);
        self.client.request("PUT", &path, Some(req))
    }

    /// Delete a SIEM destination.
    ///
    /// Calls `DELETE /api/v1/siem/destinations/{id}`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// client.streaming().delete("dest-1").unwrap();
    /// ```
    pub fn delete(&self, destination_id: &str) -> Result<()> {
        let path = format!("/api/v1/siem/destinations/{}", destination_id);
        self.client
            .request_no_response("DELETE", &path, None::<&()>)
    }

    /// Retrieve the delivery log for a SIEM destination.
    ///
    /// Calls `GET /api/v1/siem/destinations/{id}/logs`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let logs = client.streaming().delivery_log("dest-1").unwrap();
    /// for r in logs {
    ///     println!("{}: {}", r.id, r.status);
    /// }
    /// ```
    pub fn delivery_log(&self, destination_id: &str) -> Result<Vec<SIEMDeliveryRecord>> {
        let path = format!("/api/v1/siem/destinations/{}/logs", destination_id);
        let value: Value = self.client.request("GET", &path, None::<&()>)?;
        if let Value::Array(_) = &value {
            let v: Vec<SIEMDeliveryRecord> = serde_json::from_value(value)?;
            return Ok(v);
        }
        let resp: DeliveryLogResponse = serde_json::from_value(value)?;
        Ok(resp.logs.unwrap_or_default())
    }

    /// Send a test event to a SIEM destination.
    ///
    /// Calls `POST /api/v1/siem/destinations/{id}/test`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// client.streaming().test("dest-1").unwrap();
    /// ```
    pub fn test(&self, destination_id: &str) -> Result<()> {
        let path = format!("/api/v1/siem/destinations/{}/test", destination_id);
        self.client.request_no_response("POST", &path, None::<&()>)
    }

    /// Subscribe to a SIEM destination's delivery log via polling.
    ///
    /// This is a blocking polling-based stub: it repeatedly calls
    /// [`Streaming::delivery_log`] at `filter.poll_interval` and invokes
    /// `handler` for each new record. The handler should return `false` to
    /// stop the subscription.
    ///
    /// A future async release will replace this with a tokio-based SSE stream.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::{AgentTrustClient, streaming::StreamFilter};
    /// # use std::time::Duration;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let filter = StreamFilter {
    ///     destination_id: "dest-1".into(),
    ///     poll_interval: Some(Duration::from_secs(2)),
    ///     max_polls: Some(1),
    /// };
    /// client.streaming().subscribe(&filter, |record| {
    ///     println!("delivered: {}", record.id);
    ///     true
    /// }).unwrap();
    /// ```
    pub fn subscribe<F>(&self, filter: &StreamFilter, mut handler: F) -> Result<()>
    where
        F: FnMut(&SIEMDeliveryRecord) -> bool,
    {
        let interval = filter.poll_interval.unwrap_or(Duration::from_secs(5));
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut polls = 0u32;

        loop {
            let records = self.delivery_log(&filter.destination_id)?;
            for record in &records {
                if seen.insert(record.id.clone()) && !handler(record) {
                    return Ok(());
                }
            }

            polls += 1;
            if let Some(max) = filter.max_polls {
                if polls >= max {
                    return Ok(());
                }
            }
            std::thread::sleep(interval);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AgentTrustError;
    use mockito::Server;

    fn destination_body() -> &'static str {
        r#"{
            "id":"d1","org_id":"o1","name":"splunk","destination_type":"splunk",
            "endpoint_url":"https://x","is_active":true,"batch_size":100,
            "flush_interval_seconds":30
        }"#
    }

    #[test]
    fn test_create_success() {
        let mut srv = Server::new();
        let mock = srv
            .mock("POST", "/api/v1/siem/destinations")
            .with_status(200)
            .with_body(destination_body())
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let d = client
            .streaming()
            .create(&CreateSIEMDestinationRequest {
                name: "splunk".into(),
                destination_type: "splunk".into(),
                endpoint_url: "https://x".into(),
                auth_token: None,
                batch_size: None,
                flush_interval_seconds: None,
                filter_event_types: None,
            })
            .unwrap();
        assert_eq!(d.id, "d1");
        mock.assert();
    }

    #[test]
    fn test_get_not_found() {
        let mut srv = Server::new();
        let mock = srv
            .mock("GET", "/api/v1/siem/destinations/missing")
            .with_status(404)
            .with_body(r#"{"message":"not found"}"#)
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let err = client.streaming().get("missing").unwrap_err();
        assert!(matches!(err, AgentTrustError::NotFound { .. }));
        mock.assert();
    }

    #[test]
    fn test_list_validation_error() {
        let mut srv = Server::new();
        let mock = srv
            .mock("GET", "/api/v1/siem/destinations")
            .with_status(400)
            .with_body(r#"{"message":"invalid"}"#)
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let err = client.streaming().list().unwrap_err();
        assert!(matches!(err, AgentTrustError::Validation { .. }));
        mock.assert();
    }

    #[test]
    fn test_subscribe_invokes_handler() {
        let mut srv = Server::new();
        let mock = srv
            .mock("GET", "/api/v1/siem/destinations/d1/logs")
            .with_status(200)
            .with_body(
                r#"{"logs":[
                    {"id":"r1","destination_id":"d1","batch_size":1,"status":"success","delivered_at":"2026-01-01T00:00:00Z"}
                ]}"#,
            )
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let mut count = 0u32;
        let filter = StreamFilter {
            destination_id: "d1".into(),
            poll_interval: Some(Duration::from_millis(1)),
            max_polls: Some(1),
        };
        client
            .streaming()
            .subscribe(&filter, |_record| {
                count += 1;
                true
            })
            .unwrap();
        assert_eq!(count, 1);
        mock.assert();
    }

    #[test]
    fn test_delivery_log_server_error() {
        let mut srv = Server::new();
        let mock = srv
            .mock("GET", "/api/v1/siem/destinations/d1/logs")
            .with_status(500)
            .with_body(r#"{"message":"boom"}"#)
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let err = client.streaming().delivery_log("d1").unwrap_err();
        match err {
            AgentTrustError::Api { status, .. } => assert_eq!(status, 500),
            other => panic!("unexpected: {:?}", other),
        }
        mock.assert();
    }
}
