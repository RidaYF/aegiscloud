package collector

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

// suspiciousNames is a starter list for your attack scenarios — extend this
// as you build detection rules.
var suspiciousNames = []string{
	"ping", "ncat", "netcat", "nmap", "mimikatz", "psexec", "wget", "curl",
}

// ProcessMonitor implements Collector by snapshotting the running process
// list each time Collect() is called and flagging matches against
// suspiciousNames.
type ProcessMonitor struct {
	hostname string
}

func NewProcessMonitor() *ProcessMonitor {
	host, _ := os.Hostname()
	return &ProcessMonitor{hostname: host}
}

func (p *ProcessMonitor) Name() string { return "process_monitor" }

func (p *ProcessMonitor) Collect() ([]Event, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("listing processes: %w", err)
	}

	var events []Event
	for _, proc := range procs {
		name, err := proc.Name()
		if err != nil {
			continue // process may have exited between listing and inspecting it
		}

		if !isSuspicious(name) {
			continue // only emit events for what matters
		}

		username, _ := proc.Username()

		events = append(events, Event{
			Timestamp:   time.Now().UTC(),
			Hostname:    p.hostname,
			EventType:   "process_creation",
			Process:     name,
			User:        username,
			Severity:    "medium",
			Description: fmt.Sprintf("Process matching suspicious pattern: %s", name),
		})
	}
	return events, nil
}

func isSuspicious(name string) bool {
	lower := strings.ToLower(name)
	for _, s := range suspiciousNames {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}
