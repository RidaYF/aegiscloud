package transport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"aegiscloud-agent/internal/collector"
)

// Forwarder sends batches of events to the backend over HTTP(S).
type Forwarder struct {
	endpoint string
	client   *http.Client
}

func NewForwarder(endpoint string) *Forwarder {
	return &Forwarder{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 5 * time.Second},
	}
}

// Send POSTs a batch of events as a JSON array.
func (f *Forwarder) Send(events []collector.Event) error {
	if len(events) == 0 {
		return nil
	}

	body, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("marshaling events: %w", err)
	}

	resp, err := f.client.Post(f.endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("sending events: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("backend rejected events: status %d", resp.StatusCode)
	}
	return nil
}