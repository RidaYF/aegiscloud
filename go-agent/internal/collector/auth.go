package collector

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

// authLogPath is Debian/Ubuntu's default. On RHEL/CentOS this is
// /var/log/secure instead.
const authLogPath = "/var/log/auth.log"

// AuthMonitor tails the auth log and emits an event for each new line
// containing a failed-login marker, since the last time Collect() ran.
type AuthMonitor struct {
	hostname string
	offset   int64
}

func NewAuthMonitor() *AuthMonitor {
	host, _ := os.Hostname()
	return &AuthMonitor{hostname: host}
}

func (a *AuthMonitor) Name() string { return "auth_monitor" }

func (a *AuthMonitor) Collect() ([]Event, error) {
	file, err := os.Open(authLogPath)
	if err != nil {
		return nil, fmt.Errorf("opening auth log: %w", err)
	}
	defer file.Close()

	if _, err := file.Seek(a.offset, 0); err != nil {
		return nil, err
	}

	var events []Event
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Failed password") {
			user := extractUser(line)
			events = append(events, Event{
				Timestamp:   time.Now().UTC(),
				Hostname:    a.hostname,
				EventType:   "auth_failure",
				User:        user,
				Severity:    "medium",
				Description: "Failed password authentication attempt",
			})
		}
	}

	pos, _ := file.Seek(0, 1)
	a.offset = pos

	return events, scanner.Err()
}

func extractUser(line string) string {
	parts := strings.Fields(line)
	for i, p := range parts {
		if p == "for" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return "unknown"
}