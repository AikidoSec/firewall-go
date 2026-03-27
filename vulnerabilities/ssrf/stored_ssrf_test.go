package ssrf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckStoredSSRF(t *testing.T) {
	t.Run("returns result with hostname and privateIP", func(t *testing.T) {
		result := CheckStoredSSRF("evil.com", []string{"169.254.169.254"})
		require.NotNil(t, result)
		assert.Equal(t, "evil.com", result.Hostname)
		assert.Equal(t, "169.254.169.254", result.PrivateIP)
	})

	t.Run("returns nil when no IMDS IP", func(t *testing.T) {
		assert.Nil(t, CheckStoredSSRF("example.com", []string{"8.8.8.8"}))
	})
}
