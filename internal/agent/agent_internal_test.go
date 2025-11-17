package agent

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOnMiddlewareInstalled(t *testing.T) {
	t.Run("sets MiddlewareInstalled to 1", func(t *testing.T) {
		// Reset the value before test
		stateCollector.SetMiddlewareInstalled(false)

		OnMiddlewareInstalled()

		value := stateCollector.IsMiddlewareInstalled()
		assert.True(t, value, "MiddlewareInstalled should be true")
	})

	t.Run("can be called multiple times", func(t *testing.T) {
		// Reset the value before test
		stateCollector.SetMiddlewareInstalled(false)

		OnMiddlewareInstalled()
		OnMiddlewareInstalled()
		OnMiddlewareInstalled()

		value := stateCollector.IsMiddlewareInstalled()
		assert.True(t, value, "MiddlewareInstalled should remain true")
	})
}

func TestOnDomain(t *testing.T) {
	t.Run("calls storeDomain correctly", func(t *testing.T) {
		// Reset hostnames before test
		_ = stateCollector.GetAndClearHostnames()

		OnDomain("example.com", 443)

		hostnames := stateCollector.GetAndClearHostnames()

		require.Contains(t, hostnames, aikido_types.Hostname{
			URL: "example.com", Port: 443, Hits: 1,
		}, "domain should be stored")
	})
}
