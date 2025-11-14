package agent

import (
	"sync/atomic"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOnMiddlewareInstalled(t *testing.T) {
	t.Run("sets MiddlewareInstalled to 1", func(t *testing.T) {
		// Reset the value before test
		atomic.StoreUint32(&middlewareInstalled, 0)

		OnMiddlewareInstalled()

		value := atomic.LoadUint32(&middlewareInstalled)
		assert.Equal(t, uint32(1), value, "MiddlewareInstalled should be set to 1")
	})

	t.Run("can be called multiple times", func(t *testing.T) {
		// Reset the value before test
		atomic.StoreUint32(&middlewareInstalled, 0)

		OnMiddlewareInstalled()
		OnMiddlewareInstalled()
		OnMiddlewareInstalled()

		value := atomic.LoadUint32(&middlewareInstalled)
		assert.Equal(t, uint32(1), value, "MiddlewareInstalled should remain 1 after multiple calls")
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
