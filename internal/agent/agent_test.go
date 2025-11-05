package agent_test

import (
	"sync/atomic"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOnMiddlewareInstalled(t *testing.T) {
	t.Run("sets MiddlewareInstalled to 1", func(t *testing.T) {
		// Reset the value before test
		atomic.StoreUint32(&globals.MiddlewareInstalled, 0)

		agent.OnMiddlewareInstalled()

		value := atomic.LoadUint32(&globals.MiddlewareInstalled)
		assert.Equal(t, uint32(1), value, "MiddlewareInstalled should be set to 1")
	})

	t.Run("can be called multiple times", func(t *testing.T) {
		// Reset the value before test
		atomic.StoreUint32(&globals.MiddlewareInstalled, 0)

		agent.OnMiddlewareInstalled()
		agent.OnMiddlewareInstalled()
		agent.OnMiddlewareInstalled()

		value := atomic.LoadUint32(&globals.MiddlewareInstalled)
		assert.Equal(t, uint32(1), value, "MiddlewareInstalled should remain 1 after multiple calls")
	})
}

func TestOnDomain(t *testing.T) {
	t.Run("calls storeDomain correctly", func(t *testing.T) {
		// Reset hostnames before test
		globals.HostnamesMutex.Lock()
		globals.Hostnames = make(map[string]map[uint32]uint64)
		globals.HostnamesMutex.Unlock()

		agent.OnDomain("example.com", 443)

		globals.HostnamesMutex.Lock()
		defer globals.HostnamesMutex.Unlock()

		require.Contains(t, globals.Hostnames, "example.com", "domain should be stored")
		assert.Equal(t, uint64(1), globals.Hostnames["example.com"][443], "count should be 1")
	})
}
