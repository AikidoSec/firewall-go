package http

import (
	"net"

	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/ipaddr"
)

// ipAllowedToAccessRoute checks if the IP address is allowed to access the route.
func ipAllowedToAccessRoute(ip string, matches []config.Endpoint) bool {
	if ip != "" && isLocalhostIP(ip) {
		return true
	}

	if len(matches) == 0 {
		return true
	}

	for _, endpoint := range matches {
		if ip == "" {
			return false // No IP was recognized.
		}

		if !ipAllowed(ip, endpoint) {
			return false // Checks the entire array for 1 match (contains).
		}
	}

	return true
}

func ipAllowed(remoteAddress string, endpoint config.Endpoint) bool {
	ip, err := ipaddr.Parse(remoteAddress)
	if err != nil {
		return false
	}

	if endpoint.AllowedIPAddresses.Count == 0 {
		return true
	}

	return endpoint.AllowedIPAddresses.Matches(ip)
}

func isLocalhostIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP != nil && parsedIP.IsLoopback() {
		return true
	}
	return false
}
