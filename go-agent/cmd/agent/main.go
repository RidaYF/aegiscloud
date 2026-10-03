// Command agent is the AegisCloud AI telemetry agent. It runs each
// registered collector on a fixed interval and forwards whatever events
// they produce to the backend.
package main

import (
	"flag"
	"log"
	"time"

	"aegiscloud-agent/internal/collector"
	"aegiscloud-agent/internal/transport"
)

func main() {
	endpoint := flag.String("endpoint", "http://localhost:8000/api/events", "backend URL to forward events to")
	interval := flag.Duration("interval", 10*time.Second, "how often to run each collector")
	flag.Parse()

	collectors := []collector.Collector{
		collector.NewProcessMonitor(),
		collector.NewNetworkMonitor(),
		collector.NewAuthMonitor(),
	}

	forwarder := transport.NewForwarder(*endpoint)

	log.Printf("aegiscloud-agent starting: %d collectors, interval=%s, endpoint=%s",
		len(collectors), *interval, *endpoint)

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	for range ticker.C {
		for _, c := range collectors {
			events, err := c.Collect()
			if err != nil {
				log.Printf("[%s] collect error: %v", c.Name(), err)
				continue
			}
			if len(events) == 0 {
				continue
			}
			if err := forwarder.Send(events); err != nil {
				log.Printf("[%s] forward error: %v", c.Name(), err)
				continue
			}
			log.Printf("[%s] forwarded %d event(s)", c.Name(), len(events))
		}
	}
}