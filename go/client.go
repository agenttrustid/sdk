package agenttrust

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the default AgentTrust ID gateway URL.
	DefaultBaseURL = "http://localhost:8080"
	// DefaultTimeout is the default HTTP request timeout.
	DefaultTimeout = 30 * time.Second
)

// Client is the main AgentTrust ID SDK entry point.
//
// It provides access to all AgentTrust ID API sub-services through typed fields:
// Agents, Tokens, Actions, and Telemetry.
//
// Create a client using NewClient with functional options, or use FromEnv
// to configure from environment variables.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client

	// Agents provides agent registration and lifecycle management.
	Agents *AgentsAPI
	// Tokens provides capability token issuance, verification, and revocation.
	Tokens *TokensAPI
	// Actions provides pre-flight action authorization checks.
	Actions *ActionsAPI
	// Telemetry provides agent behavior telemetry reporting.
	Telemetry *TelemetryAPI
	// Federation provides OIDC federation operations.
	Federation *FederationAPI
	// WIMSE provides workload identity token operations.
	WIMSE *WIMSEAPI
	// Guardian provides direct Guardian policy evaluation.
	Guardian *GuardianAPI
	// Streaming provides SIEM streaming destination management.
	Streaming *StreamingAPI
	// Delegations provides agent-to-agent delegation management.
	Delegations *DelegationsAPI
	// Sessions provides AgentTrust session management.
	Sessions *SessionsAPI
	// Approvals provides AgentTrust elevation approval management.
	Approvals *ApprovalsAPI
	// MCP provides MCP proxy tool-calling.
	MCP *MCPAPI
}

// Option configures the Client. Use the With* functions to create options.
type Option func(*Client)

// WithBaseURL sets the AgentTrust ID gateway base URL.
// Default: "http://localhost:8080"
func WithBaseURL(url string) Option {
	return func(c *Client) {
		c.baseURL = strings.TrimRight(url, "/")
	}
}

// WithAPIKey sets the organization API key (e.g., "sk_live_xxx").
// The key is sent as an X-API-Key header on all requests.
func WithAPIKey(key string) Option {
	return func(c *Client) {
		c.apiKey = key
	}
}

// WithTimeout sets the HTTP request timeout.
// Default: 30 seconds.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.httpClient.Timeout = d
	}
}

// WithHTTPClient sets a custom *http.Client for all API requests.
// This overrides the timeout set by WithTimeout.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		c.httpClient = hc
	}
}

// NewClient creates a new AgentTrust ID client with the given options.
//
// Example:
//
//	client := ati.NewClient(
//	    ati.WithBaseURL("http://localhost:8080"),
//	    ati.WithAPIKey("sk_live_xxx"),
//	    ati.WithTimeout(10 * time.Second),
//	)
func NewClient(opts ...Option) *Client {
	c := &Client{
		baseURL: DefaultBaseURL,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	c.Agents = &AgentsAPI{client: c}
	c.Tokens = &TokensAPI{client: c}
	c.Actions = &ActionsAPI{client: c}
	c.Telemetry = &TelemetryAPI{client: c}
	c.Federation = &FederationAPI{client: c}
	c.WIMSE = &WIMSEAPI{client: c}
	c.Guardian = &GuardianAPI{client: c}
	c.Streaming = &StreamingAPI{client: c}
	c.Delegations = &DelegationsAPI{client: c}
	c.Sessions = &SessionsAPI{client: c}
	c.Approvals = &ApprovalsAPI{client: c}
	c.MCP = &MCPAPI{client: c}

	return c
}

// FromEnv creates a client configured from environment variables.
//
//	AGENTTRUST_URL       - Gateway URL (fallback: AGENTTRUST_BASE_URL, default: http://localhost:8080)
//	AGENTTRUST_API_KEY   - Organization API key (sk_live_xxx)
func FromEnv() *Client {
	var opts []Option

	baseURL := os.Getenv("AGENTTRUST_URL")
	if baseURL == "" {
		baseURL = os.Getenv("AGENTTRUST_BASE_URL")
	}
	if baseURL != "" {
		opts = append(opts, WithBaseURL(baseURL))
	}

	apiKey := os.Getenv("AGENTTRUST_API_KEY")
	if apiKey != "" {
		opts = append(opts, WithAPIKey(apiKey))
	}

	return NewClient(opts...)
}

// BaseURL returns the configured gateway base URL.
func (c *Client) BaseURL() string {
	return c.baseURL
}

// Health checks the AgentTrust ID service health.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var resp HealthResponse
	if err := c.doRequest(ctx, http.MethodGet, "/health", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// doRequest performs an HTTP request against the AgentTrust ID API.
// It handles JSON encoding/decoding, API key headers, and error mapping.
//
// If body is nil, no request body is sent.
// If result is nil, the response body is discarded (but errors are still checked).
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	return c.doRequestWithHeaders(ctx, method, path, body, result, nil)
}

// doRequestWithHeaders is doRequest with additional per-request headers (e.g.
// X-Agent-ID / X-Session-ID for the MCP proxy).
func (c *Client) doRequestWithHeaders(ctx context.Context, method, path string, body interface{}, result interface{}, headers map[string]string) error {
	url := c.baseURL + path

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return &AgentTrustError{
				Message: fmt.Sprintf("failed to marshal request body: %v", err),
				Code:    "MARSHAL_ERROR",
			}
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return &NetworkError{AgentTrustError{
			Message: fmt.Sprintf("failed to create request: %v", err),
			Code:    "NETWORK_ERROR",
		}}
	}

	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &NetworkError{AgentTrustError{
			Message: fmt.Sprintf("request failed: %v", err),
			Code:    "NETWORK_ERROR",
		}}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return &NetworkError{AgentTrustError{
			Message: fmt.Sprintf("failed to read response: %v", err),
			Code:    "NETWORK_ERROR",
		}}
	}

	// Check for HTTP errors
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Try to extract error message from response body
		message := fmt.Sprintf("HTTP %d error", resp.StatusCode)
		var errResp struct {
			Message string `json:"message"`
			Error   string `json:"error"`
		}
		if json.Unmarshal(respBody, &errResp) == nil {
			switch {
			case errResp.Message != "":
				message = errResp.Message
			case errResp.Error != "":
				message = errResp.Error
			}
		}
		return newErrorFromStatus(resp.StatusCode, message)
	}

	// Decode response body if a result target is provided
	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return &AgentTrustError{
				Message: fmt.Sprintf("failed to decode response: %v", err),
				Code:    "UNMARSHAL_ERROR",
			}
		}
	}

	return nil
}
