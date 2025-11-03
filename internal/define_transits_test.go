package internal_test

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal"
	"github.com/AikidoSec/firewall-go/internal/transits"
	"github.com/stretchr/testify/assert"
)

func TestDefineTransits(t *testing.T) {
	defer transits.SetOSSinkFunction(nil)

	t.Run("sets function when nil", func(t *testing.T) {
		transits.SetOSSinkFunction(nil)

		internal.DefineTransits()

		assert.NotNil(t, transits.GetOSSinkFunction())
	})

	t.Run("does not override existing function", func(t *testing.T) {
		called := false
		existing := func(file string) error {
			called = true
			return nil
		}
		transits.SetOSSinkFunction(existing)

		internal.DefineTransits()

		fn := transits.GetOSSinkFunction()
		_ = fn("test.txt")
		assert.True(t, called, "should still be the original function")
	})
}
