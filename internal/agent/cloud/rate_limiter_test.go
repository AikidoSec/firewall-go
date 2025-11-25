package cloud

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// resetAttackDetectedEvents resets the global state for testing
func resetAttackDetectedEvents() {
	attackDetectedEventsSentAtMutex.Lock()
	defer attackDetectedEventsSentAtMutex.Unlock()
	attackDetectedEventsSentAt = []int64{}
}

func TestShouldSendAttackDetectedEvent(t *testing.T) {
	t.Run("returns true and adds events when under limit", func(t *testing.T) {
		resetAttackDetectedEvents()

		// Test single call
		result := shouldSendAttackDetectedEvent()
		assert.True(t, result, "should return true when no events have been sent")
		assert.Equal(t, 1, len(attackDetectedEventsSentAt), "should add event to list")

		// Test multiple calls (under the limit of 100)
		for i := 0; i < 50; i++ {
			result := shouldSendAttackDetectedEvent()
			assert.True(t, result, "should return true for event %d", i+2)
		}
		assert.Equal(t, 51, len(attackDetectedEventsSentAt), "should have added all events")
	})

	t.Run("returns false and does not add events when limit is reached or exceeded", func(t *testing.T) {
		resetAttackDetectedEvents()

		// Send exactly maxAttackDetectedEventsPerInterval events
		for i := 0; i < maxAttackDetectedEventsPerInterval; i++ {
			result := shouldSendAttackDetectedEvent()
			assert.True(t, result, "should return true for event %d", i+1)
		}
		assert.Equal(t, maxAttackDetectedEventsPerInterval, len(attackDetectedEventsSentAt), "should have added all events up to limit")

		// The next call should return false and not add to the list
		initialCount := len(attackDetectedEventsSentAt)
		result := shouldSendAttackDetectedEvent()
		assert.False(t, result, "should return false when limit is reached")
		assert.Equal(t, initialCount, len(attackDetectedEventsSentAt), "should not add event when limit is exceeded")

		// Verify subsequent calls also return false
		for i := 0; i < 10; i++ {
			result := shouldSendAttackDetectedEvent()
			assert.False(t, result, "should return false for subsequent calls")
		}
		assert.Equal(t, initialCount, len(attackDetectedEventsSentAt), "should not add any more events")
	})

	t.Run("filters old events and keeps recent events", func(t *testing.T) {
		resetAttackDetectedEvents()

		// Manually add both old and recent events
		attackDetectedEventsSentAtMutex.Lock()
		currentTime := time.Now().UnixMilli()
		oldTime := currentTime - attackDetectedEventsIntervalInMs - 1000   // 1 second older than interval
		recentTime := currentTime - (attackDetectedEventsIntervalInMs / 2) // 30 minutes ago
		attackDetectedEventsSentAt = []int64{oldTime, recentTime}
		attackDetectedEventsSentAtMutex.Unlock()

		// Wait a bit to ensure current time is different
		time.Sleep(10 * time.Millisecond)

		// Should return true because old event was filtered out
		result := shouldSendAttackDetectedEvent()
		assert.True(t, result, "should return true after filtering out old events")

		// Verify old event was removed and recent event was kept
		attackDetectedEventsSentAtMutex.Lock()
		hasOldEvent := false
		hasRecentEvent := false
		for _, eventTime := range attackDetectedEventsSentAt {
			if eventTime == oldTime {
				hasOldEvent = true
			}
			if eventTime == recentTime {
				hasRecentEvent = true
			}
		}
		attackDetectedEventsSentAtMutex.Unlock()
		assert.False(t, hasOldEvent, "old event should have been filtered out")
		assert.True(t, hasRecentEvent, "recent event should be kept")
		assert.Equal(t, 2, len(attackDetectedEventsSentAt), "should have recent event plus the new one")
	})

	t.Run("thread safety with concurrent calls", func(t *testing.T) {
		resetAttackDetectedEvents()

		const numGoroutines = 50
		const callsPerGoroutine = 2

		var wg sync.WaitGroup
		results := make(chan bool, numGoroutines*callsPerGoroutine)

		// Launch multiple goroutines calling the function concurrently
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < callsPerGoroutine; j++ {
					result := shouldSendAttackDetectedEvent()
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
		attackDetectedEventsSentAtMutex.Lock()
		finalCount := len(attackDetectedEventsSentAt)
		attackDetectedEventsSentAtMutex.Unlock()
		assert.Equal(t, trueCount, finalCount, "final count should match number of true results")
	})
}
