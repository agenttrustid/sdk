// Package agenttrust provides a Go SDK for the AgentTrust.
//
// agenttrust enables secure, auditable AI agent operations through identity
// management, capability tokens, pre-flight action checks, and telemetry
// reporting.
package agenttrust

import "fmt"

// AgentTrustError is the base error type for all AgentTrust ID SDK errors.
// It contains a human-readable message, an error code, and the HTTP status code
// from the API response (if applicable).
type AgentTrustError struct {
	// Message is the human-readable error description.
	Message string `json:"message"`
	// Code is the machine-readable error code (e.g., "AUTH_FAILED", "NETWORK_ERROR").
	Code string `json:"code"`
	// Status is the HTTP status code from the API response, or 0 if not applicable.
	Status int `json:"-"`
}

// Error implements the error interface.
func (e *AgentTrustError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("ati: %s (code=%s, status=%d)", e.Message, e.Code, e.Status)
	}
	return fmt.Sprintf("ati: %s", e.Message)
}

// AuthenticationError indicates that authentication failed (HTTP 401).
// This typically means the API key is invalid or missing.
type AuthenticationError struct {
	AgentTrustError
}

// AuthorizationError indicates that authorization was denied (HTTP 403).
// The caller does not have sufficient permissions for the requested operation.
type AuthorizationError struct {
	AgentTrustError
}

// ValidationError indicates that the request failed validation (HTTP 400).
// Check the error message for details about which fields are invalid.
type ValidationError struct {
	AgentTrustError
}

// NetworkError indicates a network-level failure such as a connection refused,
// timeout, or DNS resolution failure.
type NetworkError struct {
	AgentTrustError
}

// ElevationRequiredError indicates the action requires approval before proceeding.
// The ApprovalID field contains the ID of the pending approval request.
type ElevationRequiredError struct {
	AgentTrustError
	// ApprovalID is the ID of the pending approval to approve or deny.
	ApprovalID string
}

// NotFoundError indicates the requested resource was not found (HTTP 404).
type NotFoundError struct {
	AgentTrustError
}

// newErrorFromStatus creates the appropriate typed error based on the HTTP status code.
func newErrorFromStatus(status int, message string) error {
	switch status {
	case 401:
		return &AuthenticationError{AgentTrustError{
			Message: message,
			Code:    "AUTH_FAILED",
			Status:  status,
		}}
	case 403:
		return &AuthorizationError{AgentTrustError{
			Message: message,
			Code:    "AUTH_DENIED",
			Status:  status,
		}}
	case 400:
		return &ValidationError{AgentTrustError{
			Message: message,
			Code:    "VALIDATION_ERROR",
			Status:  status,
		}}
	case 404:
		return &NotFoundError{AgentTrustError{
			Message: message,
			Code:    "NOT_FOUND",
			Status:  status,
		}}
	default:
		return &AgentTrustError{
			Message: message,
			Code:    fmt.Sprintf("HTTP_%d", status),
			Status:  status,
		}
	}
}

