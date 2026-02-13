package ssrf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindHostnameInUserInput(t *testing.T) {
	t.Run("returns false if user input and hostname are empty", func(t *testing.T) {
		assert.False(t, findHostnameInUserInput("", "", 0))
	})

	t.Run("returns false if user input is empty", func(t *testing.T) {
		assert.False(t, findHostnameInUserInput("", "example.com", 0))
	})

	t.Run("returns false if hostname is empty", func(t *testing.T) {
		assert.False(t, findHostnameInUserInput("http://example.com", "", 0))
	})

	t.Run("parses hostname from user input", func(t *testing.T) {
		assert.True(t, findHostnameInUserInput("http://localhost", "localhost", 0))
	})

	t.Run("parses hostname from user input with path", func(t *testing.T) {
		assert.True(t, findHostnameInUserInput("http://localhost/path", "localhost", 0))
	})

	t.Run("does not parse hostname with misspelled protocol", func(t *testing.T) {
		assert.False(t, findHostnameInUserInput("http:/localhost", "localhost", 0))
	})

	t.Run("does not parse hostname without protocol separator", func(t *testing.T) {
		assert.False(t, findHostnameInUserInput("http:localhost", "localhost", 0))
	})

	t.Run("does not parse hostname with misspelled protocol and path", func(t *testing.T) {
		assert.False(t, findHostnameInUserInput("http:/localhost/path/path", "localhost", 0))
	})

	t.Run("parses hostname without protocol and with path", func(t *testing.T) {
		assert.True(t, findHostnameInUserInput("localhost/path/path", "localhost", 0))
	})

	t.Run("flags ftp as protocol", func(t *testing.T) {
		assert.True(t, findHostnameInUserInput("ftp://localhost", "localhost", 0))
	})

	t.Run("parses hostname without protocol", func(t *testing.T) {
		assert.True(t, findHostnameInUserInput("localhost", "localhost", 0))
	})

	t.Run("ignores invalid urls", func(t *testing.T) {
		assert.False(t, findHostnameInUserInput("http://", "localhost", 0))
	})

	t.Run("user input is smaller than hostname", func(t *testing.T) {
		assert.False(t, findHostnameInUserInput("localhost", "localhost localhost", 0))
	})

	t.Run("finds IP address inside URL", func(t *testing.T) {
		assert.True(t, findHostnameInUserInput("http://169.254.169.254/latest/meta-data/", "169.254.169.254", 0))
	})

	t.Run("finds IP address with strange notation", func(t *testing.T) {
		assert.True(t, findHostnameInUserInput("http://2130706433", "2130706433", 0))
		assert.True(t, findHostnameInUserInput("http://127.1", "127.1", 0))
		assert.True(t, findHostnameInUserInput("http://127.0.1", "127.0.1", 0))
	})

	t.Run("works with ports", func(t *testing.T) {
		assert.False(t, findHostnameInUserInput("http://localhost", "localhost", 8080))
		assert.True(t, findHostnameInUserInput("http://localhost:8080", "localhost", 8080))
		assert.True(t, findHostnameInUserInput("http://localhost:8080", "localhost", 0))
		assert.False(t, findHostnameInUserInput("http://localhost:8080", "localhost", 4321))
	})

	t.Run("loopback IPv6 found", func(t *testing.T) {
		assert.True(t, findHostnameInUserInput("http://[::1]:8081", "::1", 0))
	})

	t.Run("loopback IPv6 with zeros found", func(t *testing.T) {
		assert.True(t, findHostnameInUserInput("http://[0000:0000:0000:0000:0000:0000:0000:0001]:8081", "0000:0000:0000:0000:0000:0000:0000:0001", 0))
	})

	t.Run("different capitalization found", func(t *testing.T) {
		assert.True(t, findHostnameInUserInput("http://localHost:8081", "localhost", 0))
	})

	t.Run("2130706433 found", func(t *testing.T) {
		assert.True(t, findHostnameInUserInput("http://2130706433:8081", "2130706433", 0))
	})

	t.Run("0x7f000001 found", func(t *testing.T) {
		assert.True(t, findHostnameInUserInput("http://0x7f000001:8081", "0x7f000001", 0))
	})

	t.Run("0177.0.0.01 found", func(t *testing.T) {
		assert.True(t, findHostnameInUserInput("http://0177.0.0.01:8081", "0177.0.0.01", 0))
	})

	t.Run("0x7f.0x0.0x0.0x1 found", func(t *testing.T) {
		assert.True(t, findHostnameInUserInput("http://0x7f.0x0.0x0.0x1:8081", "0x7f.0x0.0x0.0x1", 0))
	})

	t.Run("::ffff:127.0.0.1 found", func(t *testing.T) {
		assert.True(t, findHostnameInUserInput("http://[::ffff:127.0.0.1]:8081", "::ffff:127.0.0.1", 0))
	})

	t.Run("loopback IPv6 not found for different hostname", func(t *testing.T) {
		assert.False(t, findHostnameInUserInput("http://[::1]:8081", "localhost", 0))
	})

	t.Run("loopback IPv6 with zeros not found for different hostname", func(t *testing.T) {
		assert.False(t, findHostnameInUserInput("http://[0000:0000:0000:0000:0000:0000:0000:0001]:8081", "localhost", 0))
	})

	t.Run("different capitalization not found for different hostname", func(t *testing.T) {
		assert.False(t, findHostnameInUserInput("http://localHost:8081", "example.com", 0))
	})

	t.Run("2130706433 not found for different hostname", func(t *testing.T) {
		assert.False(t, findHostnameInUserInput("http://2130706433:8081", "example.com", 0))
	})

	t.Run("0x7f000001 not found for different hostname", func(t *testing.T) {
		assert.False(t, findHostnameInUserInput("http://0x7f000001:8081", "example.com", 0))
	})

	t.Run("0177.0.0.01 not found for different hostname", func(t *testing.T) {
		assert.False(t, findHostnameInUserInput("http://0177.0.0.01:8081", "example.com", 0))
	})

	t.Run("0x7f.0x0.0x0.0x1 not found for different hostname", func(t *testing.T) {
		assert.False(t, findHostnameInUserInput("http://0x7f.0x0.0x0.0x1:8081", "example.com", 0))
	})

	t.Run("::ffff:127.0.0.1 not found for different hostname", func(t *testing.T) {
		assert.False(t, findHostnameInUserInput("http://[::ffff:127.0.0.1]:8081", "example.com", 0))
	})
}
