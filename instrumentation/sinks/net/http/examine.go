package http

import (
	"net/http"
	"strconv"

	"github.com/AikidoSec/firewall-go/instrumentation/hooks"
	"github.com/AikidoSec/firewall-go/zen"
)

func Examine(r *http.Request) error {
	if !zen.ShouldProtect() {
		return nil
	}

	hooks.OnOperationCall("net/http.Client.Do", hooks.OperationKindOutgoingHTTP)

	if r.URL == nil {
		return nil
	}

	hostname := r.URL.Hostname()
	port := getPort(r)

	// Report any hostnames to the dashboard
	hooks.OnDomain(hostname, uint32(port))

	if hooks.ShouldBlockHostname(hostname) {
		return zen.ErrOutboundBlocked(hostname)
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
