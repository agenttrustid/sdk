//! Error types for the AgentTrust ID SDK.
//!
//! All fallible operations return `Result<T, AgentTrustError>`. Specific error variants
//! allow callers to match on the kind of failure (authentication, authorization,
//! network, etc.) using standard Rust pattern matching.

use thiserror::Error;

/// The primary error type for all AgentTrust ID SDK operations.
///
/// Use pattern matching to handle specific error categories:
///
/// ```rust,no_run
/// use agenttrustid::{AgentTrustError, AgentTrustClient};
///
/// let client = AgentTrustClient::builder().build().unwrap();
/// match client.agents().get("agent-123") {
///     Ok(agent) => println!("Found: {}", agent.name),
///     Err(AgentTrustError::NotFound { .. }) => println!("Agent not found"),
///     Err(AgentTrustError::Authentication { .. }) => println!("Bad API key"),
///     Err(e) => println!("Other error: {}", e),
/// }
/// ```
#[derive(Error, Debug)]
pub enum AgentTrustError {
    /// Authentication failed (HTTP 401). Typically means an invalid or missing API key.
    #[error("authentication failed: {message}")]
    Authentication {
        /// Human-readable error description.
        message: String,
        /// HTTP status code (always 401).
        status: u16,
    },

    /// Authorization denied (HTTP 403). The caller lacks sufficient permissions.
    #[error("authorization denied: {message}")]
    Authorization {
        /// Human-readable error description.
        message: String,
        /// HTTP status code (always 403).
        status: u16,
    },

    /// Request validation failed (HTTP 400). Check the message for field-level details.
    #[error("validation error: {message}")]
    Validation {
        /// Human-readable error description.
        message: String,
        /// HTTP status code (always 400).
        status: u16,
    },

    /// The requested resource was not found (HTTP 404).
    #[error("not found: {message}")]
    NotFound {
        /// Human-readable error description.
        message: String,
        /// HTTP status code (always 404).
        status: u16,
    },

    /// A network-level failure occurred (connection refused, timeout, DNS failure, etc.).
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    /// A pre-flight action check returned "denied".
    #[error("action denied: {message}")]
    ActionDenied {
        /// Reason the action was denied.
        message: String,
        /// The check ID from the Guardian, if available.
        check_id: Option<String>,
    },

    /// The action requires elevated approval before it can proceed.
    #[error("elevation required: {message}")]
    ElevationRequired {
        /// Human-readable description of the elevation requirement.
        message: String,
        /// The approval request ID to track or approve.
        approval_id: String,
    },

    /// The Guardian service is unreachable and fail_open is false.
    #[error("guardian unavailable: {message}")]
    GuardianUnavailable {
        /// Human-readable description of the connectivity failure.
        message: String,
    },

    /// A generic API error for status codes not covered by the specific variants.
    #[error("api error ({status}): {message}")]
    Api {
        /// Human-readable error description from the API response.
        message: String,
        /// Machine-readable error code (e.g., "HTTP_500").
        code: String,
        /// HTTP status code.
        status: u16,
    },

    /// JSON serialization or deserialization failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// A cryptographic operation failed (key generation, signing, or PEM
    /// encoding/parsing).
    #[error("crypto error: {message}")]
    Crypto {
        /// Human-readable description of the failure.
        message: String,
    },
}

/// A type alias for `std::result::Result<T, AgentTrustError>`.
pub type Result<T> = std::result::Result<T, AgentTrustError>;

/// Create the appropriate `AgentTrustError` variant from an HTTP status code and message.
pub(crate) fn error_from_status(status: u16, message: String) -> AgentTrustError {
    match status {
        401 => AgentTrustError::Authentication { message, status },
        403 => AgentTrustError::Authorization { message, status },
        400 => AgentTrustError::Validation { message, status },
        404 => AgentTrustError::NotFound { message, status },
        _ => AgentTrustError::Api {
            message,
            code: format!("HTTP_{}", status),
            status,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_from_status_401() {
        let err = error_from_status(401, "bad key".to_string());
        assert!(matches!(
            err,
            AgentTrustError::Authentication { status: 401, .. }
        ));
        assert!(err.to_string().contains("bad key"));
    }

    #[test]
    fn test_error_from_status_403() {
        let err = error_from_status(403, "forbidden".to_string());
        assert!(matches!(
            err,
            AgentTrustError::Authorization { status: 403, .. }
        ));
    }

    #[test]
    fn test_error_from_status_400() {
        let err = error_from_status(400, "invalid".to_string());
        assert!(matches!(
            err,
            AgentTrustError::Validation { status: 400, .. }
        ));
    }

    #[test]
    fn test_error_from_status_404() {
        let err = error_from_status(404, "not found".to_string());
        assert!(matches!(err, AgentTrustError::NotFound { status: 404, .. }));
    }

    #[test]
    fn test_error_from_status_500() {
        let err = error_from_status(500, "server error".to_string());
        match err {
            AgentTrustError::Api { code, status, .. } => {
                assert_eq!(code, "HTTP_500");
                assert_eq!(status, 500);
            }
            _ => panic!("expected AgentTrustError::Api"),
        }
    }

    #[test]
    fn test_error_display() {
        let err = AgentTrustError::ActionDenied {
            message: "not allowed".to_string(),
            check_id: Some("chk-1".to_string()),
        };
        assert_eq!(err.to_string(), "action denied: not allowed");
    }
}
