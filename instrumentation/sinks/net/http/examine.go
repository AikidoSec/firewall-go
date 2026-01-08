package http

import (
	"net/http"
	"strconv"

	"github.com/AikidoSec/firewall-go/internal/agent"
)

func Examine(r *http.Request) {
	if r.URL == nil {
		return
	}

	hostname := r.URL.Hostname()
	port := getPort(r)

	go agent.OnDomain(hostname, uint32(port))
}

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
