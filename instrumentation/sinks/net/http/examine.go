package http

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/AikidoSec/firewall-go/instrumentation/hooks"
	"github.com/AikidoSec/firewall-go/instrumentation/operation"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/zen"
	"golang.org/x/net/idna"
)

func Examine(r *http.Request) error {
	if !zen.ShouldProtect() {
		return nil
	}

	hooks.OnOperationCall("net/http.Client.Do", operation.KindOutgoingHTTP)

	if r.URL == nil {
		return nil
	}

	hostname := r.URL.Hostname()
	// Normalise to lowercase Unicode so block list entries (stored as Unicode)
	// match regardless of whether the URL used punycode or Unicode labels
	// (e.g. "xn--mnchen-3ya.de" and "münchen.de" both become "münchen.de").
	if normalised, err := idna.Lookup.ToUnicode(hostname); err == nil {
		hostname = normalised
	} else {
		hostname = strings.ToLower(hostname)
	}
	port := getPort(r)

	// Report any hostnames to the dashboard
	hooks.OnDomain(hostname, uint32(port))

	// If bypassed IP, report hostname, but don't attempt to block it
	if request.IsBypassed(r.Context()) {
		return nil
	}

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
