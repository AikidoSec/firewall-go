package zen_test

import (
	"context"
	"testing"

	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
)

func TestShutdown(t *testing.T) {
	t.Run("does not panic and returns no error", func(t *testing.T) {
		var err error
		assert.NotPanics(t, func() {
			err = zen.Shutdown(context.Background())
		})
		assert.NoError(t, err)
	})
}
