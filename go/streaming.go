package agenttrust

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// StreamingAPI provides SIEM streaming destination management.
type StreamingAPI struct {
	client *Client
}

// SIEMDestination represents a configured SIEM streaming destination.
type SIEMDestination struct {
	ID                   string   `json:"id"`
	OrgID                string   `json:"org_id"`
	Name                 string   `json:"name"`
	DestinationType      string   `json:"destination_type"`
	EndpointURL          string   `json:"endpoint_url"`
	AuthToken            string   `json:"auth_token,omitempty"`
	IsActive             bool     `json:"is_active"`
	BatchSize            int      `json:"batch_size"`
	FlushIntervalSeconds int      `json:"flush_interval_seconds"`
	FilterEventTypes     []string `json:"filter_event_types,omitempty"`
	CreatedAt            string   `json:"created_at,omitempty"`
	UpdatedAt            string   `json:"updated_at,omitempty"`
}

// CreateSIEMDestinationRequest contains the parameters for creating a SIEM destination.
type CreateSIEMDestinationRequest struct {
	Name                 string   `json:"name"`
	DestinationType      string   `json:"destination_type"`
	EndpointURL          string   `json:"endpoint_url"`
	AuthToken            string   `json:"auth_token,omitempty"`
	BatchSize            int      `json:"batch_size,omitempty"`
	FlushIntervalSeconds int      `json:"flush_interval_seconds,omitempty"`
	FilterEventTypes     []string `json:"filter_event_types,omitempty"`
}

// UpdateSIEMDestinationRequest contains the parameters for updating a SIEM destination.
type UpdateSIEMDestinationRequest struct {
	Name                 string   `json:"name,omitempty"`
	EndpointURL          string   `json:"endpoint_url,omitempty"`
	AuthToken            string   `json:"auth_token,omitempty"`
	IsActive             *bool    `json:"is_active,omitempty"`
	BatchSize            int      `json:"batch_size,omitempty"`
	FlushIntervalSeconds int      `json:"flush_interval_seconds,omitempty"`
	FilterEventTypes     []string `json:"filter_event_types,omitempty"`
}

// SIEMDeliveryRecord represents a delivery attempt to a SIEM destination.
type SIEMDeliveryRecord struct {
	ID            string    `json:"id"`
	DestinationID string    `json:"destination_id"`
	BatchSize     int       `json:"batch_size"`
	Status        string    `json:"status"`
	StatusCode    int       `json:"status_code,omitempty"`
	ErrorMessage  string    `json:"error_message,omitempty"`
	DeliveredAt   time.Time `json:"delivered_at"`
}

// siemDestinationListResponse wraps the list response.
type siemDestinationListResponse struct {
	Destinations []SIEMDestination `json:"destinations"`
	Total        int               `json:"total"`
}

// siemDeliveryLogResponse wraps the delivery log response.
type siemDeliveryLogResponse struct {
	Logs  []SIEMDeliveryRecord `json:"logs"`
	Total int                  `json:"total"`
}

// Create creates a new SIEM streaming destination.
func (s *StreamingAPI) Create(ctx context.Context, req CreateSIEMDestinationRequest) (*SIEMDestination, error) {
	var resp SIEMDestination
	if err := s.client.doRequest(ctx, http.MethodPost, "/api/v1/siem/destinations", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// List lists all SIEM streaming destinations.
func (s *StreamingAPI) List(ctx context.Context) ([]SIEMDestination, error) {
	var resp siemDestinationListResponse
	if err := s.client.doRequest(ctx, http.MethodGet, "/api/v1/siem/destinations", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Destinations, nil
}

// Get retrieves a specific SIEM streaming destination.
func (s *StreamingAPI) Get(ctx context.Context, id string) (*SIEMDestination, error) {
	var resp SIEMDestination
	path := fmt.Sprintf("/api/v1/siem/destinations/%s", id)
	if err := s.client.doRequest(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Update updates a SIEM streaming destination.
func (s *StreamingAPI) Update(ctx context.Context, id string, req UpdateSIEMDestinationRequest) (*SIEMDestination, error) {
	var resp SIEMDestination
	path := fmt.Sprintf("/api/v1/siem/destinations/%s", id)
	if err := s.client.doRequest(ctx, http.MethodPut, path, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Delete deletes a SIEM streaming destination.
func (s *StreamingAPI) Delete(ctx context.Context, id string) error {
	path := fmt.Sprintf("/api/v1/siem/destinations/%s", id)
	return s.client.doRequest(ctx, http.MethodDelete, path, nil, nil)
}

// DeliveryLog retrieves the delivery log for a SIEM destination.
func (s *StreamingAPI) DeliveryLog(ctx context.Context, id string) ([]SIEMDeliveryRecord, error) {
	var resp siemDeliveryLogResponse
	path := fmt.Sprintf("/api/v1/siem/destinations/%s/logs", id)
	if err := s.client.doRequest(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Logs, nil
}

// Test sends a test event to a SIEM destination.
func (s *StreamingAPI) Test(ctx context.Context, id string) error {
	path := fmt.Sprintf("/api/v1/siem/destinations/%s/test", id)
	return s.client.doRequest(ctx, http.MethodPost, path, nil, nil)
}
