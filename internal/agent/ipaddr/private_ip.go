package ipaddr

import (
	"sync"
)

var (
	privateIPRanges     *MatchList
	privateIPRangesOnce sync.Once
)

// initPrivateIPRanges initializes the private IP ranges matcher
// based on the Node.js implementation's PRIVATE_IP_RANGES and PRIVATE_IPV6_RANGES
func initPrivateIPRanges() {
	privateIPRangesOnce.Do(func() {
		// IPv4 private ranges (RFC compliant)
		privateIPv4Ranges := []string{
			"0.0.0.0/8",          // "This" network (RFC 1122)
			"10.0.0.0/8",         // Private-Use Networks (RFC 1918)
			"100.64.0.0/10",      // Shared Address Space (RFC 6598)
			"127.0.0.0/8",        // Loopback (RFC 1122)
			"169.254.0.0/16",     // Link Local (RFC 3927)
			"172.16.0.0/12",      // Private-Use Networks (RFC 1918)
			"192.0.0.0/24",       // IETF Protocol Assignments (RFC 5736)
			"192.0.2.0/24",       // TEST-NET-1 (RFC 5737)
			"192.31.196.0/24",    // AS112 Redirection Anycast (RFC 7535)
			"192.52.193.0/24",    // Automatic Multicast Tunneling (RFC 7450)
			"192.88.99.0/24",     // 6to4 Relay Anycast (RFC 3068)
			"192.168.0.0/16",     // Private-Use Networks (RFC 1918)
			"192.175.48.0/24",    // AS112 Redirection Anycast (RFC 7535)
			"198.18.0.0/15",      // Network Interconnect Device Benchmark Testing (RFC 2544)
			"198.51.100.0/24",    // TEST-NET-2 (RFC 5737)
			"203.0.113.0/24",     // TEST-NET-3 (RFC 5737)
			"224.0.0.0/4",        // Multicast (RFC 3171)
			"240.0.0.0/4",        // Reserved for Future Use (RFC 1112)
			"255.255.255.255/32", // Limited Broadcast (RFC 919)
		}

		// IPv6 private ranges
		privateIPv6Ranges := []string{
			"::/128",        // Unspecified address (RFC 4291)
			"::1/128",       // Loopback address (RFC 4291)
			"fc00::/7",      // Unique local address (ULA) (RFC 4193)
			"fe80::/10",     // Link-local address (LLA) (RFC 4291)
			"100::/64",      // Discard prefix (RFC 6666)
			"2001:db8::/32", // Documentation prefix (RFC 3849)
			"3fff::/20",     // Documentation prefix (RFC 9637)
			"::ffff:0:0/96", // IPv4-mapped IPv6 addresses
		}

		// Combine all ranges
		allPrivateRanges := make([]string, 0, len(privateIPv4Ranges)+len(privateIPv6Ranges))
		allPrivateRanges = append(allPrivateRanges, privateIPv4Ranges...)
		allPrivateRanges = append(allPrivateRanges, privateIPv6Ranges...)

		// Build match list from all private ranges
		privateIPRanges = new(MatchList)
		*privateIPRanges = BuildMatchList("privateIPs", "Private IP ranges", allPrivateRanges)
	})
}

// IsPrivateIP checks if an IP address is a private/local IP address.
// This matches the Node.js implementation's isPrivateIP function.
// Private IPs are always allowed even when an allow list is configured.
func IsPrivateIP(ip string) bool {
	// Quick validation for empty or obviously invalid inputs
	if ip == "" {
		return false
	}

	initPrivateIPRanges()

	ipAddress, err := Parse(ip)
	if err != nil {
		return false
	}

	return privateIPRanges.Matches(ipAddress)
}
