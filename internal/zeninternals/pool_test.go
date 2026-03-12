package zeninternals

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPool_Get_CreatesNewInstance(t *testing.T) {
	callCount := 0
	pool := NewPool(func() *wasmInstance {
		callCount++
		return &wasmInstance{createdAt: time.Now()}
	})

	instance, err := pool.Get()

	require.NoError(t, err)
	assert.NotNil(t, instance)
	assert.Equal(t, 1, callCount)
}

func TestPool_Get_ReusesIdleInstance(t *testing.T) {
	callCount := 0
	pool := NewPool(func() *wasmInstance {
		callCount++
		return &wasmInstance{createdAt: time.Now()}
	})

	instance1, _ := pool.Get()
	pool.Put(instance1)
	instance2, err := pool.Get()

	require.NoError(t, err)
	assert.Same(t, instance1, instance2)
	assert.Equal(t, 1, callCount)
}

func TestPool_Get_DiscardsExpiredInstance(t *testing.T) {
	callCount := 0
	pool := NewPool(func() *wasmInstance {
		callCount++
		return &wasmInstance{createdAt: time.Now()}
	})

	expiredInstance := &wasmInstance{createdAt: time.Now().Add(-instanceMaxAge - time.Second)}
	pool.Put(expiredInstance)

	instance, err := pool.Get()

	require.NoError(t, err)
	assert.NotSame(t, expiredInstance, instance)
	assert.Equal(t, 1, callCount)
}

func TestPool_Get_InstanceWhenAllInstancesExpired(t *testing.T) {
	pool := NewPool(func() *wasmInstance {
		return &wasmInstance{createdAt: time.Now()}
	})

	// Fill pool with expired instances
	for range maxIdleInstances {
		pool.Put(&wasmInstance{createdAt: time.Now().Add(-instanceMaxAge - time.Second)})
	}

	instance, err := pool.Get()

	assert.NoError(t, err)
	assert.NotNil(t, instance)
}

func TestPool_Concurrency(t *testing.T) {
	pool := NewPool(func() *wasmInstance {
		return &wasmInstance{createdAt: time.Now()}
	})

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			instance, err := pool.Get()
			if err == nil {
				pool.Put(instance)
			}
		}()
	}
	wg.Wait()
}
