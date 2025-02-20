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

		allowedIPAddresses := endpoint.AllowedIPAddresses

		// Check if the remote address is in the allowed IP addresses
		for _, allowedIP := range allowedIPAddresses {
			if allowedIP == ip {
				return true
			}
		}

		// If the remote address is not allowed, return false
		return false
	}

	return true
}
