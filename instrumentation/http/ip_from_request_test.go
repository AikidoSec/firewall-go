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

func TestGetClientIP_SinglePublicIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "5.6.7.8")

	assert.Equal(t, "5.6.7.8", GetClientIP(r))
}

func TestGetClientIP_CommaSeparated_ReturnsFirstPublic(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "5.6.7.8, 9.10.11.12")

	assert.Equal(t, "5.6.7.8", GetClientIP(r))
}

func TestGetClientIP_CommaSeparated_SkipsPrivateIPs(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	// 10.0.0.1 is private, 5.6.7.8 is public
	r.Header.Set("X-Forwarded-For", "10.0.0.1, 5.6.7.8")

	assert.Equal(t, "5.6.7.8", GetClientIP(r))
}

func TestGetClientIP_AllPrivateIPs_FallsBackToRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "10.0.0.1, 192.168.1.1, 127.0.0.1")

	assert.Equal(t, "1.2.3.4", GetClientIP(r))
}

func TestGetClientIP_InvalidIPInHeader_FallsBackToRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "not-an-ip")

	assert.Equal(t, "1.2.3.4", GetClientIP(r))
}

func TestGetClientIP_EmptyHeader_UsesRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "")

	assert.Equal(t, "1.2.3.4", GetClientIP(r))
}

func TestGetClientIP_IPv4WithPort(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "5.6.7.8:9000")

	assert.Equal(t, "5.6.7.8", GetClientIP(r))
}

func TestGetClientIP_IPv6Brackets(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "[2001:db8::1]")

	// 2001:db8::/32 is documentation range (private), so falls back
	assert.Equal(t, "1.2.3.4", GetClientIP(r))
}

func TestGetClientIP_IPv6BracketsWithPort(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	// Use a public IPv6 address
	r.Header.Set("X-Forwarded-For", "[2607:f8b0:4004:c09::6a]:9000")

	assert.Equal(t, "2607:f8b0:4004:c09::6a", GetClientIP(r))
}

func TestGetClientIP_BareIPv6Public(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Forwarded-For", "2607:f8b0:4004:c09::6a")

	assert.Equal(t, "2607:f8b0:4004:c09::6a", GetClientIP(r))
}

func TestGetClientIP_CustomHeader(t *testing.T) {
	t.Setenv("AIKIDO_CLIENT_IP_HEADER", "X-Real-IP")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	r.Header.Set("X-Real-IP", "5.6.7.8")

	assert.Equal(t, "5.6.7.8", GetClientIP(r))
}

func TestGetClientIP_CustomHeaderNotPresent_FallsBackToRemoteAddr(t *testing.T) {
	t.Setenv("AIKIDO_CLIENT_IP_HEADER", "X-Real-IP")

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	// X-Real-IP not set

	assert.Equal(t, "1.2.3.4", GetClientIP(r))
}

func TestGetClientIP_DefaultHeaderNotUsedWhenCustomSet(t *testing.T) {
	t.Setenv("AIKIDO_CLIENT_IP_HEADER", "X-Real-IP")

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
