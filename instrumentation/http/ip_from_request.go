package http

import (
	"net/http"
	"net/netip"
	"os"
	"strings"

	"github.com/AikidoSec/firewall-go/internal/agent/ipaddr"
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
func GetClientIP(r *http.Request) string {
	socketIP := parseRemoteAddr(r.RemoteAddr)

	if !isTrustProxy() {
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

// GetClientIPForAuthorization returns the client's IP address to be used for
// authorization decisions (IP allow/block lists).
//
// For security-critical authorization decisions, this function uses the TCP
// socket IP address by default, which cannot be spoofed by the client.
//
// Proxy headers (X-Forwarded-For, etc.) are only trusted for authorization
// when AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS is explicitly set to true.
// This prevents attackers from bypassing IP restrictions by forging headers.
//
// Note: This is separate from GetClientIP() which may use headers for
// logging and monitoring purposes where spoofing is less critical.
func GetClientIPForAuthorization(r *http.Request) string {
	socketIP := parseRemoteAddr(r.RemoteAddr)

	// For authorization decisions, only trust proxy headers if explicitly enabled
	if !isTrustProxyForIPRestrictions() {
		return socketIP
	}

	// If explicitly enabled, fall back to the standard GetClientIP logic
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

// isTrustProxyForIPRestrictions returns whether proxy headers should be trusted
// for IP-based authorization decisions (allow/block lists).
//
// Defaults to false for security. Only set AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS=true
// if your application is behind a trusted reverse proxy and you need to enforce
// IP restrictions based on the client IP from proxy headers.
//
// WARNING: Setting this to true without proper proxy configuration allows attackers
// to bypass IP restrictions by forging X-Forwarded-For headers.
func isTrustProxyForIPRestrictions() bool {
	val := os.Getenv("AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS")
	if val == "" {
		return false
	}
	switch strings.ToLower(val) {
	case "true", "1", "yes", "y", "on":
		return true
	default:
		return false
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
