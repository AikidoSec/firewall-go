package http_functions

import (
	"github.com/AikidoSec/firewall-go/internal/helpers"
	. "github.com/AikidoSec/zen-internals-agent/aikido_types"
)

// ipAllowedToAccessRoute checks if the IP address is allowed to access the route.
func ipAllowedToAccessRoute(ip string, matches []Endpoint) bool {
	if ip != "" && helpers.IsLocalhostIP(ip) {
		return true
	}
	if matches == nil || len(matches) == 0 {
		return true
	}

	for _, endpoint := range matches {
		if len(endpoint.AllowedIPAddresses) == 0 {
			continue
		}

		if ip == "" {
			return false // No IP was recognized.
		}

		if !ipAllowed(ip, endpoint) {
			return false // Checks the entire array for 1 match (contains).
		}
	}

	return true
}

func ipAllowed(remoteAddress string, endpoint Endpoint) bool {
	for _, allowedIP := range endpoint.AllowedIPAddresses {
		if allowedIP == remoteAddress {
			// The IP is in the allowlist, so allow
			return true
		}
	}
	// The IP is not in the allowlist, so block
	return false
}
