package collector

import (
	"fmt"
	"os"
	"time"

	psnet "github.com/shirou/gopsutil/v3/net"
)

// watchedPorts are ports we consider "unexpected" for outbound traffic from
// a lab host — tune this per your scenarios. This is intentionally simple;
// your Python detection engine will do smarter correlation later.
var watchedPorts = map[uint32]bool{
	4444: true, // classic reverse-shell / Metasploit default
	1337: true,
	6666: true,
}

type NetworkMonitor struct {
	hostname string
}

func NewNetworkMonitor() *NetworkMonitor {
	host, _ := os.Hostname()
	return &NetworkMonitor{hostname: host}
}

func (n *NetworkMonitor) Name() string { return "network_monitor" }

func (n *NetworkMonitor) Collect() ([]Event, error) {
	conns, err := psnet.Connections("inet") // all IPv4/IPv6 TCP+UDP connections
	if err != nil {
		return nil, fmt.Errorf("listing connections: %w", err)
	}

	var events []Event
	for _, c := range conns {
		if c.Status != "ESTABLISHED" {
			continue // only care about live outbound connections
		}
		if !watchedPorts[c.Raddr.Port] {
			continue
		}

		events = append(events, Event{
			Timestamp:   time.Now().UTC(),
			Hostname:    n.hostname,
			EventType:   "network_connection",
			SourceIP:    c.Laddr.IP,
			DestIP:      c.Raddr.IP,
			DestPort:    int(c.Raddr.Port),
			Severity:    "high",
			Description: fmt.Sprintf("Outbound connection to watched port %d", c.Raddr.Port),
		})
	}
	return events, nil
}