// Package collector defines the shared Event type and the Collector interface
// that every monitor (process, network, auth) implements.
package collector

import "time"

// Event is the normalized shape every collector must produce.
type Event struct {
	Timestamp   time.Time `json:"timestamp"`
	Hostname    string    `json:"hostname"`
	EventType   string    `json:"event_type"` // e.g. "process_creation", "network_connection", "auth_failure"
	Process     string    `json:"process,omitempty"`
	User        string    `json:"user,omitempty"`
	SourceIP    string    `json:"source_ip,omitempty"`
	DestIP      string    `json:"dest_ip,omitempty"`
	DestPort    int       `json:"dest_port,omitempty"`
	Severity    string    `json:"severity"` // "low", "medium", "high"
	Description string    `json:"description,omitempty"`
}

// Collector is the interface every monitor implements. Collect() runs one
// pass and returns whatever events it found.
type Collector interface {
	Name() string
	Collect() ([]Event, error)
}