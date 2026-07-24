package http

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGetClientIPForAuthorization_DefaultBehavior tests that by default,
// GetClientIPForAuthorization uses the socket IP and ignores headers.
func TestGetClientIPForAuthorization_DefaultBehavior(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "5.6.7.8")

	// By default, should use socket IP for authorization, not header
	assert.Equal(t, "1.2.3.4", GetClientIPForAuthorization(r))
}

// TestGetClientIPForAuthorization_ExplicitlyDisabled tests that when
// AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS is explicitly set to false,
// the socket IP is used.
func TestGetClientIPForAuthorization_ExplicitlyDisabled(t *testing.T) {
	t.Setenv("AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS", "false")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "5.6.7.8")

	assert.Equal(t, "1.2.3.4", GetClientIPForAuthorization(r))
}

// TestGetClientIPForAuthorization_ExplicitlyEnabled tests that when
// AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS is explicitly set to true,
// the header IP is used.
func TestGetClientIPForAuthorization_ExplicitlyEnabled(t *testing.T) {
	t.Setenv("AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS", "true")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "5.6.7.8")

	assert.Equal(t, "5.6.7.8", GetClientIPForAuthorization(r))
}

// TestGetClientIPForAuthorization_EnabledVariants tests various ways to enable
// the trust proxy for IP restrictions.
func TestGetClientIPForAuthorization_EnabledVariants(t *testing.T) {
	for _, val := range []string{"true", "1", "yes", "y", "on", "True", "TRUE"} {
		t.Run(val, func(t *testing.T) {
			t.Setenv("AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS", val)

			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = "1.2.3.4:1234"
			r.Header.Set("X-Forwarded-For", "5.6.7.8")

			assert.Equal(t, "5.6.7.8", GetClientIPForAuthorization(r))
		})
	}
}

// TestGetClientIPForAuthorization_DisabledVariants tests various ways to disable
// the trust proxy for IP restrictions (including default empty string).
func TestGetClientIPForAuthorization_DisabledVariants(t *testing.T) {
	for _, val := range []string{"", "false", "0", "no", "n", "off", "False", "FALSE", "invalid"} {
		t.Run(val, func(t *testing.T) {
			if val != "" {
				t.Setenv("AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS", val)
			}

			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = "1.2.3.4:1234"
			r.Header.Set("X-Forwarded-For", "5.6.7.8")

			assert.Equal(t, "1.2.3.4", GetClientIPForAuthorization(r))
		})
	}
}

// TestGetClientIPForAuthorization_NoHeader tests that when no header is present,
// the socket IP is used regardless of the setting.
func TestGetClientIPForAuthorization_NoHeader(t *testing.T) {
	t.Setenv("AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS", "true")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"

	assert.Equal(t, "1.2.3.4", GetClientIPForAuthorization(r))
}

// TestGetClientIPForAuthorization_PrivateIPInHeader tests that when the header
// contains only private IPs, the socket IP is used.
func TestGetClientIPForAuthorization_PrivateIPInHeader(t *testing.T) {
	t.Setenv("AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS", "true")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "10.0.0.1, 192.168.1.1")

	assert.Equal(t, "1.2.3.4", GetClientIPForAuthorization(r))
}

// TestGetClientIPForAuthorization_CustomHeader tests that the custom header
// is respected when AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS is enabled.
func TestGetClientIPForAuthorization_CustomHeader(t *testing.T) {
	t.Setenv("AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS", "true")
	t.Setenv("AIKIDO_CLIENT_IP_HEADER", "X-Real-IP")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "5.6.7.8")
	r.Header.Set("X-Real-IP", "9.10.11.12")

	assert.Equal(t, "9.10.11.12", GetClientIPForAuthorization(r))
}

// TestGetClientIPForAuthorization_IndependentFromGetClientIP tests that
// GetClientIPForAuthorization is independent from AIKIDO_TRUST_PROXY setting.
func TestGetClientIPForAuthorization_IndependentFromGetClientIP(t *testing.T) {
	// AIKIDO_TRUST_PROXY is true by default, but AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS is false
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "5.6.7.8")

	// GetClientIP should use header (default behavior)
	assert.Equal(t, "5.6.7.8", GetClientIP(r))

	// GetClientIPForAuthorization should use socket IP (secure default)
	assert.Equal(t, "1.2.3.4", GetClientIPForAuthorization(r))
}

// TestGetClientIPForAuthorization_BothSettingsEnabled tests that when both
// AIKIDO_TRUST_PROXY and AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS are enabled,
// both functions use the header.
func TestGetClientIPForAuthorization_BothSettingsEnabled(t *testing.T) {
	t.Setenv("AIKIDO_TRUST_PROXY", "true")
	t.Setenv("AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS", "true")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "5.6.7.8")

	assert.Equal(t, "5.6.7.8", GetClientIP(r))
	assert.Equal(t, "5.6.7.8", GetClientIPForAuthorization(r))
}

// TestGetClientIPForAuthorization_BothSettingsDisabled tests that when both
// AIKIDO_TRUST_PROXY and AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS are disabled,
// both functions use the socket IP.
func TestGetClientIPForAuthorization_BothSettingsDisabled(t *testing.T) {
	t.Setenv("AIKIDO_TRUST_PROXY", "false")
	t.Setenv("AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS", "false")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "5.6.7.8")

	assert.Equal(t, "1.2.3.4", GetClientIP(r))
	assert.Equal(t, "1.2.3.4", GetClientIPForAuthorization(r))
}
