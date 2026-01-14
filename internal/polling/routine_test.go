package polling

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestStart(t *testing.T) {
	var callCount int64

	r := Start(10*time.Millisecond, func() {
		atomic.AddInt64(&callCount, 1)
	})

	time.Sleep(35 * time.Millisecond)
	r.Stop()

	assert.Greater(t, atomic.LoadInt64(&callCount), int64(1))
}

func TestStop(t *testing.T) {
	var callCount int64

	r := Start(10*time.Millisecond, func() {
		atomic.AddInt64(&callCount, 1)
	})

	time.Sleep(25 * time.Millisecond)
	r.Stop() // Waits for goroutine to complete

	finalCount := atomic.LoadInt64(&callCount)
	time.Sleep(30 * time.Millisecond)

	assert.Equal(t, finalCount, atomic.LoadInt64(&callCount))
}

func TestReset(t *testing.T) {
	var callCount int64

	r := Start(50*time.Millisecond, func() {
		atomic.AddInt64(&callCount, 1)
	})

	time.Sleep(30 * time.Millisecond)
	firstCount := atomic.LoadInt64(&callCount)
	assert.Equal(t, int64(0), firstCount, "Should not have fired yet")

	// Reset to a faster interval
	r.Reset(10 * time.Millisecond)

	time.Sleep(35 * time.Millisecond)
	r.Stop()

	finalCount := atomic.LoadInt64(&callCount)
	assert.Greater(t, finalCount, int64(1), "Should have fired multiple times after reset")
}
