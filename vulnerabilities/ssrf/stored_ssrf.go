package ssrf

import "slices"

// StoredSSRFResult holds the details of a detected stored SSRF attack.
type StoredSSRFResult struct {
	Hostname  string
	PrivateIP string
}

// CheckStoredSSRF checks if a hostname resolves to an IMDS IP address,
// indicating a potential stored SSRF attack (e.g., DNS spoofing or /etc/hosts poisoning).
// Returns nil if no attack is detected.
func CheckStoredSSRF(hostname string, resolvedIPs []string) *StoredSSRFResult {
	if isTrustedHostname(hostname) {
		return nil
	}

	if slices.Contains(resolvedIPs, hostname) {
		// if the hostname itself is an IP then we don't want to block this, as it's just an IMDS request, not stored ssrf.
		return nil
	}

	imdsIP := resolvesToIMDSIP(resolvedIPs)
	if imdsIP == "" {
		return nil
	}

	return &StoredSSRFResult{
		Hostname:  hostname,
		PrivateIP: imdsIP,
	}
}
