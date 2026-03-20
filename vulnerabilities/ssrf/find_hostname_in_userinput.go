package ssrf

import (
	"net/url"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/text/unicode/norm"
)

func findHostnameInUserInput(userInput, hostname string, port uint32) bool {
	if len(userInput) <= 1 {
		return false
	}
	if hostname == "" {
		return false
	}

	hostnameOptions := getHostnameOptions(hostname)
	if len(hostnameOptions) == 0 {
		return false
	}

	variants := []string{userInput, "http://" + userInput, "https://" + userInput}

	for _, variant := range variants {
		parsed, err := url.Parse(variant)
		if err != nil {
			continue
		}
		if parsed.Scheme == "" || parsed.Host == "" {
			continue
		}

		// Strip trailing colons from the host to handle URLs like
		// http://127.0.0.1:4000:/ where a trailing colon causes
		// Hostname() to misparse (it splits on the last colon).
		parsed.Host = strings.TrimRight(parsed.Host, ":")
		parsedHostname := strings.ToLower(parsed.Hostname())
		// NFKC-normalize to handle Unicode confusables (e.g. ⓛ → l).
		// Go's HTTP transport applies IDNA processing (which includes NFKC)
		// before dialing, so the hostname we receive at DialContext level is
		// already normalized. We must normalize the user input side to match.
		parsedHostname = norm.NFKC.String(parsedHostname)
		parsedPort := getPortFromURL(parsed)

		// Skip if both ports are set, in valid range, and don't match
		if port != 0 && parsedPort >= 0 && parsedPort <= 65535 && uint32(parsedPort) != port { //nolint:gosec // overflow impossible: guarded by parsedPort <= 65535
			continue
		}

		if slices.Contains(hostnameOptions, parsedHostname) {
			return true
		}
	}

	return false
}

// getHostnameOptions returns possible hostname representations for matching.
func getHostnameOptions(hostname string) []string {
	var options []string

	// Try parsing as-is (wrapped in a URL)
	if parsed, err := url.Parse("http://" + hostname); err == nil && parsed.Hostname() != "" {
		options = append(options, strings.ToLower(parsed.Hostname()))
	}

	// Try wrapping in brackets for IPv6 addresses like ::1
	if parsed, err := url.Parse("http://[" + hostname + "]"); err == nil && parsed.Hostname() != "" {
		lower := strings.ToLower(parsed.Hostname())
		if len(options) == 0 || options[0] != lower {
			options = append(options, lower)
		}
	}

	return options
}

// getPortFromURL extracts the port from a parsed URL.
// Returns -1 if the port string is present but invalid.
// Returns 0 if no port is specified and the scheme is not http/https.
func getPortFromURL(u *url.URL) int {
	portStr := u.Port()
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil {
			return -1
		}
		return p
	}

	switch u.Scheme {
	case "http":
		return 80
	case "https":
		return 443
	default:
		return 0
	}
}
