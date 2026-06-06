package agenttrust

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestStreamingCreate(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/siem/destinations": func(w http.ResponseWriter, r *http.Request) {
			var req CreateSIEMDestinationRequest
			json.NewDecoder(r.Body).Decode(&req)
			if req.Name != "Splunk Prod" {
				t.Errorf("expected name=Splunk Prod, got %q", req.Name)
			}
			if req.DestinationType != "splunk_hec" {
				t.Errorf("expected type=splunk_hec, got %q", req.DestinationType)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(SIEMDestination{
				ID:              "dest-1",
				Name:            req.Name,
				DestinationType: req.DestinationType,
				EndpointURL:     req.EndpointURL,
				IsActive:        true,
				BatchSize:       100,
			})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	dest, err := c.Streaming.Create(context.Background(), CreateSIEMDestinationRequest{
		Name:            "Splunk Prod",
		DestinationType: "splunk_hec",
		EndpointURL:     "https://splunk.example.com:8088/services/collector",
		AuthToken:       "splunk-token",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dest.ID != "dest-1" {
		t.Errorf("expected id=dest-1, got %q", dest.ID)
	}
	if dest.Name != "Splunk Prod" {
		t.Errorf("expected name=Splunk Prod, got %q", dest.Name)
	}
}

func TestStreamingList(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"GET /api/v1/siem/destinations": jsonHandler(200, siemDestinationListResponse{
			Destinations: []SIEMDestination{
				{ID: "dest-1", Name: "Webhook", DestinationType: "webhook", IsActive: true},
				{ID: "dest-2", Name: "Datadog", DestinationType: "datadog", IsActive: true},
			},
			Total: 2,
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	dests, err := c.Streaming.List(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dests) != 2 {
		t.Fatalf("expected 2 destinations, got %d", len(dests))
	}
	if dests[0].Name != "Webhook" {
		t.Errorf("expected first name=Webhook, got %q", dests[0].Name)
	}
}

func TestStreamingGet(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"GET /api/v1/siem/destinations/dest-1": jsonHandler(200, SIEMDestination{
			ID:              "dest-1",
			Name:            "Webhook",
			DestinationType: "webhook",
			EndpointURL:     "https://hooks.example.com/ati",
			IsActive:        true,
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	dest, err := c.Streaming.Get(context.Background(), "dest-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dest.Name != "Webhook" {
		t.Errorf("expected name=Webhook, got %q", dest.Name)
	}
}

func TestStreamingUpdate(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"PUT /api/v1/siem/destinations/dest-1": func(w http.ResponseWriter, r *http.Request) {
			var req UpdateSIEMDestinationRequest
			json.NewDecoder(r.Body).Decode(&req)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(SIEMDestination{
				ID:              "dest-1",
				Name:            req.Name,
				DestinationType: "webhook",
				IsActive:        true,
			})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	dest, err := c.Streaming.Update(context.Background(), "dest-1", UpdateSIEMDestinationRequest{
		Name: "Updated Webhook",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dest.Name != "Updated Webhook" {
		t.Errorf("expected name=Updated Webhook, got %q", dest.Name)
	}
}

func TestStreamingDelete(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"DELETE /api/v1/siem/destinations/dest-1": jsonHandler(200, map[string]string{"status": "deleted"}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	err := c.Streaming.Delete(context.Background(), "dest-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStreamingDeliveryLog(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"GET /api/v1/siem/destinations/dest-1/logs": jsonHandler(200, siemDeliveryLogResponse{
			Logs: []SIEMDeliveryRecord{
				{ID: "log-1", DestinationID: "dest-1", BatchSize: 50, Status: "success", StatusCode: 200, DeliveredAt: time.Now()},
				{ID: "log-2", DestinationID: "dest-1", BatchSize: 25, Status: "failure", StatusCode: 500, ErrorMessage: "timeout", DeliveredAt: time.Now()},
			},
			Total: 2,
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	logs, err := c.Streaming.DeliveryLog(context.Background(), "dest-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(logs) != 2 {
		t.Fatalf("expected 2 logs, got %d", len(logs))
	}
	if logs[0].Status != "success" {
		t.Errorf("expected first log status=success, got %q", logs[0].Status)
	}
	if logs[1].ErrorMessage != "timeout" {
		t.Errorf("expected second log error=timeout, got %q", logs[1].ErrorMessage)
	}
}

func TestStreamingTest(t *testing.T) {
	srv := newTestServer(map[string]http.HandlerFunc{
		"POST /api/v1/siem/destinations/dest-1/test": jsonHandler(200, map[string]interface{}{
			"success":     true,
			"status_code": 200,
		}),
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	err := c.Streaming.Test(context.Background(), "dest-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
