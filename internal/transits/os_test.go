package transits_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/transits"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetAndGetOSSinkFunction(t *testing.T) {
	defer transits.SetOSSinkFunction(nil)

	t.Run("successful call", func(t *testing.T) {
		called := false
		testFunc := func(file string) error {
			called = true
			return nil
		}

		transits.SetOSSinkFunction(testFunc)
		retrieved := transits.GetOSSinkFunction()

		require.NotNil(t, retrieved)
		err := retrieved("test.txt")
		assert.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("error propagation", func(t *testing.T) {
		expectedErr := errors.New("path traversal detected")
		testFunc := func(file string) error {
			return expectedErr
		}

		transits.SetOSSinkFunction(testFunc)
		retrieved := transits.GetOSSinkFunction()

		require.NotNil(t, retrieved)
		err := retrieved("../../../etc/passwd")
		assert.Equal(t, expectedErr, err)
	})
}

func TestGetOSSinkFunctionReturnsNilInitially(t *testing.T) {
	transits.SetOSSinkFunction(nil)
	assert.Nil(t, transits.GetOSSinkFunction())
}

func TestConcurrentSetAndGet(t *testing.T) {
	defer transits.SetOSSinkFunction(nil)

	var wg sync.WaitGroup
	iterations := 100

	// Concurrent sets
	for range iterations {
		wg.Add(1)
		go func() {
			defer wg.Done()
			transits.SetOSSinkFunction(func(file string) error { return nil })
		}()
	}

	// Concurrent gets
	for range iterations {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if fn := transits.GetOSSinkFunction(); fn != nil {
				_ = fn("test.txt")
			}
		}()
	}

	wg.Wait()
}
