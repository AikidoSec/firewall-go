package http

import (
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/AikidoSec/firewall-go/internal/agent/ipaddr"
	"github.com/AikidoSec/firewall-go/internal/log"
)

// GetClientIP returns the client's IP address from the request.
//
// By default, it trusts proxy headers and reads the client IP from the
// x-forwarded-for header (or the header named by AIKIDO_CLIENT_IP_HEADER).
// It returns the first valid non-private IP found in that header, falling
// back to the TCP remote address if none is found.
//
// Set AIKIDO_TRUST_PROXY=false to disable proxy header trust entirely and
// always use the raw TCP remote address instead.
//
// When AIKIDO_TRUST_PROXY is enabled, forwarding headers are only trusted
// if the TCP peer (r.RemoteAddr) is in the AIKIDO_TRUSTED_PROXIES list.
// AIKIDO_TRUSTED_PROXIES should be a comma-separated list of IP addresses
// or CIDR ranges (e.g., "10.0.0.1,192.168.1.0/24").
// If AIKIDO_TRUSTED_PROXIES is not set, forwarding headers are not trusted
// for security reasons, and the socket IP is always used.
func GetClientIP(r *http.Request) string {
	socketIP := parseRemoteAddr(r.RemoteAddr)

	if !isTrustProxy() {
		return socketIP
	}

	// Validate that the TCP peer is a trusted proxy before accepting forwarding headers
	if !isTrustedProxy(socketIP) {
		return socketIP
	}

	headerName := getClientIPHeaderName()
	headerValue := r.Header.Get(headerName)
	if headerValue == "" {
		return socketIP
	}

	if ip := extractFirstPublicIPFromHeader(headerValue); ip != "" {
		return ip
	}

	return socketIP
}

// isTrustProxy returns whether proxy headers should be trusted.
// Defaults to true; set AIKIDO_TRUST_PROXY=false to disable.
func isTrustProxy() bool {
	val := os.Getenv("AIKIDO_TRUST_PROXY")
	if val == "" {
		return true
	}
	switch strings.ToLower(val) {
	case "false", "0", "no", "n", "off":
		return false
	default:
		return true
	}
}

// getClientIPHeaderName returns the header name to use for the client IP.
// Defaults to "x-forwarded-for"; override with AIKIDO_CLIENT_IP_HEADER.
func getClientIPHeaderName() string {
	if name := os.Getenv("AIKIDO_CLIENT_IP_HEADER"); name != "" {
		return name
	}
	return "X-Forwarded-For"
}

// extractFirstPublicIPFromHeader parses a comma-separated list of IPs from
// a header value and returns the first valid non-private IP address.
func extractFirstPublicIPFromHeader(headerValue string) string {
	for part := range strings.SplitSeq(headerValue, ",") {
		ip := parseIPFromHeaderPart(strings.TrimSpace(part))
		if ip == "" || ipaddr.IsPrivateIP(ip) {
			continue
		}
		return ip
	}
	return ""
}

// parseIPFromHeaderPart extracts an IP address from a single header part,
// handling IPv6 bracket notation and optional port numbers.
func parseIPFromHeaderPart(s string) string {
	if s == "" {
		return ""
	}

	// IPv6 in brackets: [::1] or [::1]:port, extract between brackets
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end == -1 {
			return ""
		}
		inner := s[1:end]
		addr, err := netip.ParseAddr(inner)
		if err != nil {
			return ""
		}
		return addr.String()
	}

	// Try plain IP address first (covers bare IPv6 like ::1)
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.String()
	}

	// Try ip:port (covers IPv4 with port like 1.2.3.4:8080)
	if addrPort, err := netip.ParseAddrPort(s); err == nil {
		return addrPort.Addr().String()
	}

	return ""
}

// parseRemoteAddr extracts the IP address from an addr:port string (r.RemoteAddr).
func parseRemoteAddr(remoteAddr string) string {
	addrPort, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return ""
	}
	return addrPort.Addr().String()
}

var (
	trustedProxies     *ipaddr.MatchList
	trustedProxiesOnce sync.Once
	trustedProxiesWarn sync.Once
)

// initTrustedProxies initializes the trusted proxy matcher from AIKIDO_TRUSTED_PROXIES.
func initTrustedProxies() {
	trustedProxiesOnce.Do(func() {
		val := os.Getenv("AIKIDO_TRUSTED_PROXIES")
		if val == "" {
			// No trusted proxies configured
			trustedProxies = nil
			return
		}

		// Parse comma-separated list of IPs/CIDRs
		parts := strings.Split(val, ",")
		cidrs := make([]string, 0, len(parts))
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				cidrs = append(cidrs, trimmed)
			}
		}

		if len(cidrs) == 0 {
			trustedProxies = nil
			return
		}

		// Build match list from trusted proxy CIDRs
		matchList := ipaddr.BuildMatchList("trustedProxies", "Trusted proxy IP addresses", cidrs)
		trustedProxies = &matchList
	})
}

// isTrustedProxy checks if the given IP is in the trusted proxy list.
// If AIKIDO_TRUSTED_PROXIES is not configured, this returns false and logs a warning.
func isTrustedProxy(ip string) bool {
	initTrustedProxies()

	if trustedProxies == nil {
		// No trusted proxies configured - log warning once and reject forwarding headers
		trustedProxiesWarn.Do(func() {
			log.Warn("AIKIDO_TRUST_PROXY is enabled but AIKIDO_TRUSTED_PROXIES is not configured. " +
				"Forwarding headers will not be trusted for security reasons. " +
				"Set AIKIDO_TRUSTED_PROXIES to a comma-separated list of trusted proxy IPs/CIDRs, " +
				"or set AIKIDO_TRUST_PROXY=false to always use the socket IP.")
		})
		return false
	}

	if ip == "" {
		return false
	}

	ipAddress, err := ipaddr.Parse(ip)
	if err != nil {
		return false
	}

	return trustedProxies.Matches(ipAddress)
}
