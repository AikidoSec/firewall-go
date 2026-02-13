package http

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/state/stats"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/ssrf"
	"github.com/AikidoSec/firewall-go/zen"
)

func Examine(r *http.Request) error {
	if !zen.ShouldProtect() {
		return nil
	}

	agent.OnOperationCall("net/http.Client.Do", stats.OperationKindOutgoingHTTP)

	if r.URL == nil {
		return nil
	}

	hostname := r.URL.Hostname()
	port := getPort(r)

	// Report any hostnames to the dashboard
	go agent.OnDomain(hostname, uint32(port))

	if config.ShouldBlockHostname(hostname) {
		return zen.ErrOutboundBlocked(hostname)
	}

	err := vulnerabilities.Scan(r.Context(), "net/http.Client.Do",
		ssrf.SSRFVulnerability, &ssrf.ScanArgs{Hostname: hostname, Port: port})
	if err != nil {
		attackKind := vulnerabilities.KindSSRF
		var attackErr *vulnerabilities.AttackDetectedError
		if errors.As(err, &attackErr) {
			attackKind = attackErr.Kind
		}
		return errors.Join(zen.ErrAttackBlocked(attackKind), err)
	}

	return nil
}

// getPort number from [*http.Request]
// Returns 0 for unsupported protocols
func getPort(r *http.Request) uint32 {
	portStr := r.URL.Port()
	if portStr == "" {
		// Infer from scheme
		switch r.URL.Scheme {
		case "https":
			return 443
		case "http":
			return 80
		default:
			return 0
		}
	}
	port, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(port)
}
