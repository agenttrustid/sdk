//! The main AgentTrust ID client and builder.
//!
//! [`AgentTrustClient`] is the entry point for all AgentTrust ID API operations. Create one using
//! the builder pattern or from environment variables:
//!
//! ```rust,no_run
//! use agenttrustid::AgentTrustClient;
//!
//! // Builder pattern
//! let client = AgentTrustClient::builder()
//!     .base_url("http://localhost:8080")
//!     .api_key("sk_live_xxx")
//!     .build()
//!     .unwrap();
//!
//! // From environment variables
//! let client = AgentTrustClient::from_env().unwrap();
//! ```

use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde::de::DeserializeOwned;
use serde::Serialize;

use std::sync::atomic::AtomicU64;

use crate::a2a::A2A;
use crate::actions::ActionsAPI;
use crate::agentcards::AgentCards;
use crate::agents::AgentsAPI;
use crate::approvals::ApprovalsAPI;
use crate::delegations::Delegations;
use crate::error::{error_from_status, AgentTrustError, Result};
use crate::federation::Federation;
use crate::mcp::Mcp;
use crate::models::{ErrorResponse, HealthResponse};
use crate::sessions::SessionsAPI;
use crate::streaming::Streaming;
use crate::telemetry::TelemetryAPI;
use crate::tokens::TokensAPI;
use crate::wimse::Wimse;

/// Default AgentTrust ID gateway URL.
pub const DEFAULT_BASE_URL: &str = "http://localhost:8080";

/// Default HTTP request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The main AgentTrust ID SDK client.
///
/// Provides access to all AgentTrust ID API sub-services through accessor methods:
/// [`agents()`](Self::agents), [`tokens()`](Self::tokens),
/// [`actions()`](Self::actions), and [`telemetry()`](Self::telemetry).
///
/// The client is cheaply cloneable (wraps an `Arc` internally via `reqwest`) and
/// safe to share across threads.
pub struct AgentTrustClient {
    pub(crate) http: reqwest::blocking::Client,
    pub(crate) base_url: String,
    pub(crate) api_key: Option<String>,
    pub(crate) agent_creds: Option<crate::credentials::AgentCredentials>,
}

impl AgentTrustClient {
    /// Create a new [`AgentTrustClientBuilder`] for configuring the client.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use agenttrustid::AgentTrustClient;
    /// use std::time::Duration;
    ///
    /// let client = AgentTrustClient::builder()
    ///     .base_url("http://localhost:8080")
    ///     .api_key("sk_live_xxx")
    ///     .timeout(Duration::from_secs(10))
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn builder() -> AgentTrustClientBuilder {
        AgentTrustClientBuilder::default()
    }

    /// Create a client configured from environment variables.
    ///
    /// Preferred variables:
    /// - `AGENTTRUST_URL` (or `AGENTTRUST_BASE_URL`): Gateway URL (default: `http://localhost:8080`)
    /// - `AGENTTRUST_API_KEY`: Organization API key (e.g., `sk_live_xxx`)
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client fails to build.
    pub fn from_env() -> Result<Self> {
        Self::from_env_with(|key| std::env::var(key).ok())
    }

    /// Like [`from_env`](Self::from_env) but reads env vars through a caller-supplied closure.
    /// Used by tests to avoid mutating real process environment.
    pub(crate) fn from_env_with<F>(reader: F) -> Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let base_url = reader("AGENTTRUST_URL")
            .filter(|v| !v.is_empty())
            .or_else(|| reader("AGENTTRUST_BASE_URL").filter(|v| !v.is_empty()))
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());

        let api_key = reader("AGENTTRUST_API_KEY").filter(|v| !v.is_empty());
        let mut builder = AgentTrustClientBuilder::default();
        builder.base_url = base_url;
        builder.api_key = api_key;
        builder.build()
    }

    /// Returns the configured base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Check the AgentTrust ID service health.
    ///
    /// Calls `GET /health` and returns the service status.
    pub fn health(&self) -> Result<HealthResponse> {
        self.request::<HealthResponse>("GET", "/health", None::<&()>)
    }

    /// Access the agents API for registration and lifecycle management.
    pub fn agents(&self) -> AgentsAPI<'_> {
        AgentsAPI { client: self }
    }

    /// Access the tokens API for issuance, verification, and revocation.
    pub fn tokens(&self) -> TokensAPI<'_> {
        TokensAPI { client: self }
    }

    /// Access the actions API for pre-flight authorization checks.
    pub fn actions(&self) -> ActionsAPI<'_> {
        ActionsAPI { client: self }
    }

    /// Access the telemetry API for reporting agent behavior events.
    pub fn telemetry(&self) -> TelemetryAPI<'_> {
        TelemetryAPI { client: self }
    }

    /// Access the sessions API for MCP session management.
    pub fn sessions(&self) -> SessionsAPI<'_> {
        SessionsAPI { client: self }
    }

    /// Access the approvals API for elevated action approval management.
    pub fn approvals(&self) -> ApprovalsAPI<'_> {
        ApprovalsAPI { client: self }
    }

    /// Access the agent cards API (A2A discovery).
    pub fn agentcards(&self) -> AgentCards<'_> {
        AgentCards { client: self }
    }

    /// Access the A2A (agent-to-agent) task dispatch API.
    pub fn a2a(&self) -> A2A<'_> {
        A2A {
            client: self,
            request_id: AtomicU64::new(0),
        }
    }

    /// Access the MCP server registry and proxy API.
    pub fn mcp(&self) -> Mcp<'_> {
        Mcp { client: self }
    }

    /// Access the delegations API.
    pub fn delegations(&self) -> Delegations<'_> {
        Delegations { client: self }
    }

    /// Access the federation (cross-org OIDC) API.
    pub fn federation(&self) -> Federation<'_> {
        Federation { client: self }
    }

    /// Access the SIEM streaming API.
    pub fn streaming(&self) -> Streaming<'_> {
        Streaming { client: self }
    }

    /// Access the WIMSE workload identity API.
    pub fn wimse(&self) -> Wimse<'_> {
        Wimse { client: self }
    }

    /// Perform an HTTP request that expects a JSON response body.
    /// Clone the transport configuration into a standalone client (no agent
    /// credentials attached), used internally so [`AgentCredentials`] can issue
    /// tokens without a self-referential type.
    pub(crate) fn clone_for_credentials(&self) -> AgentTrustClient {
        AgentTrustClient {
            http: self.http.clone(),
            base_url: self.base_url.clone(),
            api_key: self.api_key.clone(),
            agent_creds: None,
        }
    }

    /// Route runtime authorization checks (`actions().check`) through an agent's
    /// WIMSE token plus a per-request DPoP proof, in addition to any org API key.
    /// Build the credentials with [`AgentCredentials::new`].
    pub fn with_agent_credentials(mut self, ac: crate::credentials::AgentCredentials) -> Self {
        self.agent_creds = Some(ac);
        self
    }

    pub(crate) fn request<T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: Option<impl Serialize>,
    ) -> Result<T> {
        self.request_with_headers(method, path, body, &[])
    }

    /// Like [`request`](Self::request) but attaches additional per-request
    /// headers (e.g. an agent WIMSE Bearer token + DPoP proof on runtime calls,
    /// or X-Agent-ID / X-Session-ID for the MCP proxy).
    pub(crate) fn request_with_headers<T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: Option<impl Serialize>,
        extra_headers: &[(String, String)],
    ) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);

        let mut req = match method {
            "GET" => self.http.get(&url),
            "POST" => self.http.post(&url),
            "PUT" => self.http.put(&url),
            "DELETE" => self.http.delete(&url),
            "PATCH" => self.http.patch(&url),
            _ => self.http.get(&url),
        };

        req = req.header(CONTENT_TYPE, "application/json");

        if let Some(key) = &self.api_key {
            req = req.header("X-API-Key", key);
        }

        for (k, v) in extra_headers {
            req = req.header(k.as_str(), v.as_str());
        }

        if let Some(b) = body {
            req = req.json(&b);
        }

        let resp = req.send()?;
        let status = resp.status().as_u16();

        if status < 200 || status >= 300 {
            let body_text = resp.text().unwrap_or_default();
            let message = serde_json::from_str::<ErrorResponse>(&body_text)
                .map(|e| e.message)
                .unwrap_or_else(|_| format!("HTTP {} error", status));
            return Err(error_from_status(status, message));
        }

        let body_text = resp.text().unwrap_or_default();
        if body_text.is_empty() {
            // For responses with no body, try to deserialize from "{}"
            let result: T = serde_json::from_str("{}")?;
            return Ok(result);
        }
        let result: T = serde_json::from_str(&body_text)?;
        Ok(result)
    }

    /// Perform an HTTP request that does not expect a meaningful response body.
    pub(crate) fn request_no_response(
        &self,
        method: &str,
        path: &str,
        body: Option<impl Serialize>,
    ) -> Result<()> {
        let url = format!("{}{}", self.base_url, path);

        let mut req = match method {
            "GET" => self.http.get(&url),
            "POST" => self.http.post(&url),
            "PUT" => self.http.put(&url),
            "DELETE" => self.http.delete(&url),
            "PATCH" => self.http.patch(&url),
            _ => self.http.get(&url),
        };

        req = req.header(CONTENT_TYPE, "application/json");

        if let Some(key) = &self.api_key {
            req = req.header("X-API-Key", key);
        }

        if let Some(b) = body {
            req = req.json(&b);
        }

        let resp = req.send()?;
        let status = resp.status().as_u16();

        if status < 200 || status >= 300 {
            let body_text = resp.text().unwrap_or_default();
            let message = serde_json::from_str::<ErrorResponse>(&body_text)
                .map(|e| e.message)
                .unwrap_or_else(|_| format!("HTTP {} error", status));
            return Err(error_from_status(status, message));
        }

        Ok(())
    }
}

/// Builder for configuring and constructing an [`AgentTrustClient`].
pub struct AgentTrustClientBuilder {
    base_url: String,
    api_key: Option<String>,
    timeout: Duration,
    default_headers: HeaderMap,
}

impl Default for AgentTrustClientBuilder {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.to_string(),
            api_key: None,
            timeout: DEFAULT_TIMEOUT,
            default_headers: HeaderMap::new(),
        }
    }
}

impl AgentTrustClientBuilder {
    /// Set the AgentTrust ID gateway base URL.
    ///
    /// Trailing slashes are automatically trimmed.
    /// Default: `http://localhost:8080`
    pub fn base_url(mut self, url: &str) -> Self {
        self.base_url = url.trim_end_matches('/').to_string();
        self
    }

    /// Set the organization API key (e.g., `sk_live_xxx`).
    ///
    /// The key is sent as an `X-API-Key` header on all requests.
    pub fn api_key(mut self, key: &str) -> Self {
        self.api_key = Some(key.to_string());
        self
    }

    /// Set the HTTP request timeout.
    ///
    /// Default: 30 seconds.
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout = duration;
        self
    }

    /// Add a default header to all requests.
    pub fn default_header(mut self, name: &str, value: &str) -> Self {
        if let Ok(v) = HeaderValue::from_str(value) {
            if let Ok(n) = reqwest::header::HeaderName::from_bytes(name.as_bytes()) {
                self.default_headers.insert(n, v);
            }
        }
        self
    }

    /// Build the [`AgentTrustClient`].
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying HTTP client fails to build
    /// (e.g., invalid TLS configuration).
    pub fn build(self) -> Result<AgentTrustClient> {
        let http = reqwest::blocking::ClientBuilder::new()
            .timeout(self.timeout)
            .default_headers(self.default_headers)
            .build()
            .map_err(AgentTrustError::Network)?;

        Ok(AgentTrustClient {
            http,
            base_url: self.base_url.trim_end_matches('/').to_string(),
            api_key: self.api_key,
            agent_creds: None,
        })
    }
}

