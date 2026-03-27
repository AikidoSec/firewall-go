package ssrf

import (
	"github.com/AikidoSec/firewall-go/internal/agent/ipaddr"
)

var imdsIPList = ipaddr.BuildMatchList("imds", "IMDS IP addresses", []string{
	"169.254.169.254",
	"100.100.100.200",
	"fd00:ec2::254",
})

var trustedHostnames = map[string]bool{
	"metadata.google.internal": true,
	"metadata.goog":            true,
}

// isIMDSIPAddress checks if an IP matches a known IMDS address.
func isIMDSIPAddress(ip string) bool {
	parsed, err := ipaddr.Parse(ip)
	if err != nil {
		return false
	}
	return imdsIPList.Matches(parsed)
}

// isTrustedHostname checks if the hostname is a trusted cloud metadata hostname
// that should not be flagged as stored SSRF.
func isTrustedHostname(hostname string) bool {
	return trustedHostnames[hostname]
}

// resolvesToIMDSIP checks whether any of the resolved IPs are IMDS addresses.
// Returns the offending IMDS IP or empty string.
func resolvesToIMDSIP(resolvedIPs []string) string {
	for _, ip := range resolvedIPs {
		if isIMDSIPAddress(ip) {
			return ip
		}
	}
	return ""
}
