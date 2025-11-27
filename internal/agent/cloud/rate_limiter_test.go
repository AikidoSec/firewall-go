package cloud

import (
	"sync"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/slidingwindow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetAttackDetectedEvents resets the global state for testing
func resetAttackDetectedEvents() {
	attackDetectedEventsWindow = slidingwindow.New(
		attackDetectedEventsIntervalInMs,
		maxAttackDetectedEventsPerInterval,
	)
}

func TestShouldSendAttackDetectedEvent(t *testing.T) {
	t.Run("returns true when under limit", func(t *testing.T) {
		resetAttackDetectedEvents()

		// Test single call
		result := shouldSendAttackEvent()
		assert.True(t, result, "should return true when no events have been sent")

		// Test multiple calls (under the limit of 100)
		for i := range 50 {
			result := shouldSendAttackEvent()
			assert.True(t, result, "should return true for event %d", i+2)
		}
	})

	t.Run("returns false when limit is reached or exceeded", func(t *testing.T) {
		resetAttackDetectedEvents()

		// Send exactly maxAttackDetectedEventsPerInterval events
		for i := range maxAttackDetectedEventsPerInterval {
			result := shouldSendAttackEvent()
			assert.True(t, result, "should return true for event %d", i+1)
		}

		// The next call should return false and not add to the list
		result := shouldSendAttackEvent()
		assert.False(t, result, "should return false when limit is reached")

		// Verify subsequent calls also return false
		for range 10 {
			result := shouldSendAttackEvent()
			assert.False(t, result, "should return false for subsequent calls")
		}
	})

	t.Run("filters old events and keeps recent events", func(t *testing.T) {
		resetAttackDetectedEvents()

		// Manually add both old and recent events
		currentTime := time.Now().UnixMilli()
		oldTime := currentTime - attackDetectedEventsIntervalInMs - 1000 // 1 second older than interval

		for range 100 {
			require.True(t, attackDetectedEventsWindow.TryRecord(oldTime))
		}

		// Should return true because old event was filtered out
		result := shouldSendAttackEvent()
		assert.True(t, result, "should return true after filtering out old events")
	})

	t.Run("thread safety with concurrent calls", func(t *testing.T) {
		resetAttackDetectedEvents()

		const numGoroutines = 50
		const callsPerGoroutine = 2

		var wg sync.WaitGroup
		results := make(chan bool, numGoroutines*callsPerGoroutine)

		// Launch multiple goroutines calling the function concurrently
		for range numGoroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range callsPerGoroutine {
					result := shouldSendAttackEvent()
					results <- result
				}
			}()
		}

		wg.Wait()
		close(results)

		// Count true results
		trueCount := 0
		for result := range results {
			if result {
				trueCount++
			}
		}

		// Should have at most maxAttackDetectedEventsPerInterval true results
		assert.LessOrEqual(t, trueCount, maxAttackDetectedEventsPerInterval,
			"should not exceed limit even with concurrent calls")

		// Verify final count matches
		assert.Equal(t, trueCount,
			attackDetectedEventsWindow.Count(time.Now().UnixMilli()),
			"final count should match number of true results")
	})
}
