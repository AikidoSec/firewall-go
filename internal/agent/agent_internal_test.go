package agent

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
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
