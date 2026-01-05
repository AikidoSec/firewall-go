package ipaddr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsPrivateIP(t *testing.T) {
	t.Run("identifies private IPv4 addresses", func(t *testing.T) {
		// RFC 1918 private networks
		assert.True(t, IsPrivateIP("10.0.0.1"))
		assert.True(t, IsPrivateIP("172.16.0.1"))
		assert.True(t, IsPrivateIP("192.168.1.1"))

		// Loopback
		assert.True(t, IsPrivateIP("127.0.0.1"))
		assert.True(t, IsPrivateIP("127.255.255.255"))

		// Link local
		assert.True(t, IsPrivateIP("169.254.0.1"))

		// Test ranges
		assert.True(t, IsPrivateIP("0.0.0.1"))
		assert.True(t, IsPrivateIP("100.64.0.1"))
		assert.True(t, IsPrivateIP("198.18.0.1"))
	})

	t.Run("identifies private IPv6 addresses", func(t *testing.T) {
		// Loopback
		assert.True(t, IsPrivateIP("::1"))

		// Unique local address (ULA)
		assert.True(t, IsPrivateIP("fc00::1"))
		assert.True(t, IsPrivateIP("fd00::1"))

		// Link-local
		assert.True(t, IsPrivateIP("fe80::1"))

		// Documentation prefix
		assert.True(t, IsPrivateIP("2001:db8::1"))
	})

	t.Run("identifies public IPv4 addresses", func(t *testing.T) {
		assert.False(t, IsPrivateIP("8.8.8.8"))
		assert.False(t, IsPrivateIP("1.1.1.1"))
		assert.False(t, IsPrivateIP("203.0.114.1")) // Outside TEST-NET-3 range
	})

	t.Run("identifies public IPv6 addresses", func(t *testing.T) {
		assert.False(t, IsPrivateIP("2001:4860:4860::8888"))
		assert.False(t, IsPrivateIP("2606:4700:4700::1111"))
	})

	t.Run("handles invalid IP addresses", func(t *testing.T) {
		assert.False(t, IsPrivateIP("not-an-ip"))
		assert.False(t, IsPrivateIP("256.256.256.256"))
	})

	t.Run("identifies IPv6-mapped IPv4 addresses", func(t *testing.T) {
		// Private IPv4 mapped to IPv6
		assert.True(t, IsPrivateIP("::ffff:10.0.0.1"))
		assert.True(t, IsPrivateIP("::ffff:192.168.1.1"))
		assert.True(t, IsPrivateIP("::ffff:172.16.0.1"))
		assert.True(t, IsPrivateIP("::ffff:127.0.0.1"))

		// Public IPv4 mapped to IPv6
		assert.False(t, IsPrivateIP("::ffff:8.8.8.8"))
		assert.False(t, IsPrivateIP("::ffff:1.1.1.1"))
	})
}
