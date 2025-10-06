package http

import (
	"slices"

	"github.com/AikidoSec/firewall-go/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/helpers"
)

// ipAllowedToAccessRoute checks if the IP address is allowed to access the route.
func ipAllowedToAccessRoute(ip string, matches []aikido_types.Endpoint) bool {
	if ip != "" && helpers.IsLocalhostIP(ip) {
		return true
	}

	if len(matches) == 0 {
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

func ipAllowed(remoteAddress string, endpoint aikido_types.Endpoint) bool {
	return slices.Contains(endpoint.AllowedIPAddresses, remoteAddress)
}
