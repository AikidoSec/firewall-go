package ssrf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsIMDSIPAddress(t *testing.T) {
	imdsIPs := []string{
		"169.254.169.254",
		"100.100.100.200",
		"fd00:ec2::254",
		"::ffff:169.254.169.254",
		"::ffff:100.100.100.200",
	}
	for _, ip := range imdsIPs {
		assert.True(t, isIMDSIPAddress(ip), "should detect IMDS IP: %s", ip)
	}

	nonIMDSIPs := []string{
		"10.0.0.1",
		"192.168.1.1",
		"127.0.0.1",
		"8.8.8.8",
		"not-an-ip",
		"",
	}
	for _, ip := range nonIMDSIPs {
		assert.False(t, isIMDSIPAddress(ip), "should not flag: %s", ip)
	}
}

func TestIsTrustedHostname(t *testing.T) {
	assert.True(t, isTrustedHostname("metadata.google.internal"))
	assert.True(t, isTrustedHostname("metadata.goog"))
	assert.False(t, isTrustedHostname("example.com"))
	assert.False(t, isTrustedHostname(""))
}

func TestResolvesToIMDSIP(t *testing.T) {
	tests := []struct {
		name        string
		resolvedIPs []string
		hostname    string
		want        string
	}{
		{"detects IMDS IP", []string{"169.254.169.254"}, "evil.com", "169.254.169.254"},
		{"finds IMDS among multiple IPs", []string{"8.8.8.8", "100.100.100.200"}, "evil.com", "100.100.100.200"},
		{"skips IP literal (hostname equals IP)", []string{"169.254.169.254"}, "169.254.169.254", ""},
		{"skips trusted hostname", []string{"169.254.169.254"}, "metadata.google.internal", ""},
		{"ignores non-IMDS private IPs", []string{"10.0.0.1"}, "internal.example.com", ""},
		{"ignores public IPs", []string{"93.184.216.34"}, "example.com", ""},
		{"handles empty IPs", []string{}, "example.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolvesToIMDSIP(tt.resolvedIPs, tt.hostname)
			assert.Equal(t, tt.want, got)
		})
	}
}
