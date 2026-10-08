package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetClientIP_NoHeaders_UsesRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"

	assert.Equal(t, "1.2.3.4", GetClientIP(r))
}

func TestGetClientIP_TrustProxyFalse_IgnoresHeader(t *testing.T) {
	t.Setenv("AIKIDO_TRUST_PROXY", "false")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "5.6.7.8")

	assert.Equal(t, "1.2.3.4", GetClientIP(r))
}

func TestGetClientIP_TrustProxyFalseVariants(t *testing.T) {
	for _, val := range []string{"false", "0", "no", "n", "off", "False", "FALSE"} {
		t.Run(val, func(t *testing.T) {
			t.Setenv("AIKIDO_TRUST_PROXY", val)

			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = "1.2.3.4:1234"
			r.Header.Set("X-Forwarded-For", "5.6.7.8")

			assert.Equal(t, "1.2.3.4", GetClientIP(r))
		})
	}
}

func TestGetClientIP_NoTrustedProxies_IgnoresHeader(t *testing.T) {
	// When AIKIDO_TRUSTED_PROXIES is not set, forwarding headers should be ignored
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "5.6.7.8")

	assert.Equal(t, "1.2.3.4", GetClientIP(r))
}

func TestGetClientIP_UntrustedProxy_IgnoresHeader(t *testing.T) {
	// Configure trusted proxies, but request comes from untrusted IP
	t.Setenv("AIKIDO_TRUSTED_PROXIES", "10.0.0.1,192.168.1.0/24")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234" // Not in trusted list
	r.Header.Set("X-Forwarded-For", "5.6.7.8")

	assert.Equal(t, "1.2.3.4", GetClientIP(r))
}

func TestGetClientIP_TrustedProxy_SinglePublicIP(t *testing.T) {
	t.Setenv("AIKIDO_TRUSTED_PROXIES", "1.2.3.4")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "5.6.7.8")

	assert.Equal(t, "5.6.7.8", GetClientIP(r))
}

func TestGetClientIP_TrustedProxyCIDR_SinglePublicIP(t *testing.T) {
	t.Setenv("AIKIDO_TRUSTED_PROXIES", "1.2.3.0/24")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "5.6.7.8")

	assert.Equal(t, "5.6.7.8", GetClientIP(r))
}

func TestGetClientIP_TrustedProxy_CommaSeparated_ReturnsFirstPublic(t *testing.T) {
	t.Setenv("AIKIDO_TRUSTED_PROXIES", "1.2.3.4")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "5.6.7.8, 9.10.11.12")

	assert.Equal(t, "5.6.7.8", GetClientIP(r))
}

func TestGetClientIP_TrustedProxy_CommaSeparated_SkipsPrivateIPs(t *testing.T) {
	t.Setenv("AIKIDO_TRUSTED_PROXIES", "1.2.3.4")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	// 10.0.0.1 is private, 5.6.7.8 is public
	r.Header.Set("X-Forwarded-For", "10.0.0.1, 5.6.7.8")

	assert.Equal(t, "5.6.7.8", GetClientIP(r))
}

func TestGetClientIP_TrustedProxy_AllPrivateIPs_FallsBackToRemoteAddr(t *testing.T) {
	t.Setenv("AIKIDO_TRUSTED_PROXIES", "1.2.3.4")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "10.0.0.1, 192.168.1.1, 127.0.0.1")

	assert.Equal(t, "1.2.3.4", GetClientIP(r))
}

func TestGetClientIP_TrustedProxy_InvalidIPInHeader_FallsBackToRemoteAddr(t *testing.T) {
	t.Setenv("AIKIDO_TRUSTED_PROXIES", "1.2.3.4")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "not-an-ip")

	assert.Equal(t, "1.2.3.4", GetClientIP(r))
}

func TestGetClientIP_TrustedProxy_EmptyHeader_UsesRemoteAddr(t *testing.T) {
	t.Setenv("AIKIDO_TRUSTED_PROXIES", "1.2.3.4")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "")

	assert.Equal(t, "1.2.3.4", GetClientIP(r))
}

func TestGetClientIP_TrustedProxy_IPv4WithPort(t *testing.T) {
	t.Setenv("AIKIDO_TRUSTED_PROXIES", "1.2.3.4")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "5.6.7.8:9000")

	assert.Equal(t, "5.6.7.8", GetClientIP(r))
}

func TestGetClientIP_TrustedProxy_IPv6Brackets(t *testing.T) {
	t.Setenv("AIKIDO_TRUSTED_PROXIES", "1.2.3.4")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "[2001:db8::1]")

	// 2001:db8::/32 is documentation range (private), so falls back
	assert.Equal(t, "1.2.3.4", GetClientIP(r))
}

func TestGetClientIP_TrustedProxy_IPv6BracketsWithPort(t *testing.T) {
	t.Setenv("AIKIDO_TRUSTED_PROXIES", "1.2.3.4")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	// Use a public IPv6 address
	r.Header.Set("X-Forwarded-For", "[2607:f8b0:4004:c09::6a]:9000")

	assert.Equal(t, "2607:f8b0:4004:c09::6a", GetClientIP(r))
}

func TestGetClientIP_TrustedProxy_BareIPv6Public(t *testing.T) {
	t.Setenv("AIKIDO_TRUSTED_PROXIES", "1.2.3.4")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "2607:f8b0:4004:c09::6a")

	assert.Equal(t, "2607:f8b0:4004:c09::6a", GetClientIP(r))
}

func TestGetClientIP_TrustedProxy_CustomHeader(t *testing.T) {
	t.Setenv("AIKIDO_CLIENT_IP_HEADER", "X-Real-IP")
	t.Setenv("AIKIDO_TRUSTED_PROXIES", "1.2.3.4")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Real-IP", "5.6.7.8")

	assert.Equal(t, "5.6.7.8", GetClientIP(r))
}

func TestGetClientIP_TrustedProxy_CustomHeaderNotPresent_FallsBackToRemoteAddr(t *testing.T) {
	t.Setenv("AIKIDO_CLIENT_IP_HEADER", "X-Real-IP")
	t.Setenv("AIKIDO_TRUSTED_PROXIES", "1.2.3.4")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	// X-Real-IP not set

	assert.Equal(t, "1.2.3.4", GetClientIP(r))
}

func TestGetClientIP_TrustedProxy_DefaultHeaderNotUsedWhenCustomSet(t *testing.T) {
	t.Setenv("AIKIDO_CLIENT_IP_HEADER", "X-Real-IP")
	t.Setenv("AIKIDO_TRUSTED_PROXIES", "1.2.3.4")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "5.6.7.8") // not used
	r.Header.Set("X-Real-IP", "9.10.11.12")

	assert.Equal(t, "9.10.11.12", GetClientIP(r))
}

func TestGetClientIP_LoopbackRemoteAddr_NoHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"

	assert.Equal(t, "127.0.0.1", GetClientIP(r))
}

func TestGetClientIP_InvalidRemoteAddr_ReturnsEmpty(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "invalid"

	assert.Equal(t, "", GetClientIP(r))
}

func TestGetClientIP_NoRemoteAddr_NoHeader_ReturnsEmpty(t *testing.T) {
	r := &http.Request{
		Header: make(http.Header),
	}

	assert.Equal(t, "", GetClientIP(r))
}

func TestGetClientIP_MultipleTrustedProxies(t *testing.T) {
	t.Setenv("AIKIDO_TRUSTED_PROXIES", "1.2.3.4, 10.0.0.1, 192.168.1.0/24")

	tests := []struct {
		name       string
		remoteAddr string
		header     string
		expected   string
	}{
		{
			name:       "first trusted proxy",
			remoteAddr: "1.2.3.4:1234",
			header:     "5.6.7.8",
			expected:   "5.6.7.8",
		},
		{
			name:       "second trusted proxy",
			remoteAddr: "10.0.0.1:1234",
			header:     "5.6.7.8",
			expected:   "5.6.7.8",
		},
		{
			name:       "proxy in CIDR range",
			remoteAddr: "192.168.1.50:1234",
			header:     "5.6.7.8",
			expected:   "5.6.7.8",
		},
		{
			name:       "untrusted proxy",
			remoteAddr: "9.9.9.9:1234",
			header:     "5.6.7.8",
			expected:   "9.9.9.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remoteAddr
			r.Header.Set("X-Forwarded-For", tt.header)

			assert.Equal(t, tt.expected, GetClientIP(r))
		})
	}
}

func TestGetClientIP_IPv6TrustedProxy(t *testing.T) {
	t.Setenv("AIKIDO_TRUSTED_PROXIES", "2001:db8::1")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[2001:db8::1]:1234"
	r.Header.Set("X-Forwarded-For", "2607:f8b0:4004:c09::6a")

	assert.Equal(t, "2607:f8b0:4004:c09::6a", GetClientIP(r))
}

func TestGetClientIP_IPv6TrustedProxyCIDR(t *testing.T) {
	t.Setenv("AIKIDO_TRUSTED_PROXIES", "2001:db8::/32")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[2001:db8::5]:1234"
	r.Header.Set("X-Forwarded-For", "2607:f8b0:4004:c09::6a")

	assert.Equal(t, "2607:f8b0:4004:c09::6a", GetClientIP(r))
}

func TestGetClientIP_SecurityScenarios(t *testing.T) {
	t.Run("attacker cannot forge IP without trusted proxy", func(t *testing.T) {
		// Attacker tries to impersonate an allowlisted IP
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "1.2.3.4:1234"                  // Attacker's real IP
		r.Header.Set("X-Forwarded-For", "192.168.0.1") // Forged allowlisted IP

		// Without AIKIDO_TRUSTED_PROXIES, the forged header should be ignored
		assert.Equal(t, "1.2.3.4", GetClientIP(r))
	})

	t.Run("attacker cannot forge IP from untrusted proxy", func(t *testing.T) {
		t.Setenv("AIKIDO_TRUSTED_PROXIES", "10.0.0.1")

		// Attacker tries to impersonate an allowlisted IP
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "1.2.3.4:1234"                  // Attacker's real IP (not in trusted list)
		r.Header.Set("X-Forwarded-For", "192.168.0.1") // Forged allowlisted IP

		// Since 1.2.3.4 is not a trusted proxy, the forged header should be ignored
		assert.Equal(t, "1.2.3.4", GetClientIP(r))
	})

	t.Run("legitimate proxy can forward client IP", func(t *testing.T) {
		t.Setenv("AIKIDO_TRUSTED_PROXIES", "10.0.0.1")

		// Legitimate proxy forwards client IP
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "10.0.0.1:1234"             // Trusted proxy
		r.Header.Set("X-Forwarded-For", "5.6.7.8") // Real client IP

		// Since 10.0.0.1 is a trusted proxy, the header should be trusted
		assert.Equal(t, "5.6.7.8", GetClientIP(r))
	})

	t.Run("attacker cannot rotate IPs for rate limiting bypass", func(t *testing.T) {
		// Attacker tries to rotate forged IPs to bypass rate limiting
		forgedIPs := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}

		for _, forgedIP := range forgedIPs {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = "1.2.3.4:1234" // Attacker's real IP
			r.Header.Set("X-Forwarded-For", forgedIP)

			// All requests should resolve to the attacker's real IP
			assert.Equal(t, "1.2.3.4", GetClientIP(r))
		}
	})
}
