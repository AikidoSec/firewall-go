package attackwave

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLRUCache(t *testing.T) {
	t.Run("stores and retrieves values", func(t *testing.T) {
		cache := newLRUCache(10, 0)
		timestamps := []time.Time{time.Now()}

		cache.Set("ip1", timestamps)

		val, ok := cache.Get("ip1")
		assert.True(t, ok)
		assert.Equal(t, timestamps, val)
	})

	t.Run("evicts oldest entry when capacity reached", func(t *testing.T) {
		cache := newLRUCache(3, 0)

		cache.Set("ip1", []time.Time{time.Now()})
		cache.Set("ip2", []time.Time{time.Now()})
		cache.Set("ip3", []time.Time{time.Now()})
		cache.Set("ip4", []time.Time{time.Now()}) // Should evict ip1

		_, ok := cache.Get("ip1")
		assert.False(t, ok, "oldest entry should be evicted")

		_, ok = cache.Get("ip4")
		assert.True(t, ok, "newest entry should exist")
	})

	t.Run("get bumps entry to most recent", func(t *testing.T) {
		cache := newLRUCache(3, 0)

		cache.Set("ip1", []time.Time{time.Now()})
		cache.Set("ip2", []time.Time{time.Now()})
		cache.Set("ip3", []time.Time{time.Now()})

		cache.Get("ip1")                          // Bump ip1 to most recent
		cache.Set("ip4", []time.Time{time.Now()}) // Should evict ip2, not ip1

		_, ok := cache.Get("ip1")
		assert.True(t, ok, "accessed entry should not be evicted")

		_, ok = cache.Get("ip2")
		assert.False(t, ok, "ip2 should be evicted")
	})

	t.Run("entries expire after TTL", func(t *testing.T) {
		cache := newLRUCache(10, 50*time.Millisecond)

		cache.Set("ip1", []time.Time{time.Now()})

		// Should exist immediately
		_, ok := cache.Get("ip1")
		assert.True(t, ok)

		// Should be expired after TTL
		time.Sleep(100 * time.Millisecond)
		_, ok = cache.Get("ip1")
		assert.False(t, ok, "entry should be expired")
	})

	t.Run("updating entry refreshes TTL", func(t *testing.T) {
		cache := newLRUCache(10, 100*time.Millisecond)

		cache.Set("ip1", []time.Time{time.Now()})
		time.Sleep(60 * time.Millisecond)

		// Update should refresh TTL
		cache.Set("ip1", []time.Time{time.Now(), time.Now()})
		time.Sleep(60 * time.Millisecond)

		_, ok := cache.Get("ip1")
		assert.True(t, ok, "entry should still be valid after TTL refresh")
	})
}
