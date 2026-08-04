package polling

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestStart(t *testing.T) {
	var callCount int64

	r := Start(context.Background(), 10*time.Millisecond, func() {
		atomic.AddInt64(&callCount, 1)
	})

	time.Sleep(35 * time.Millisecond)
	r.Stop()

	assert.Greater(t, atomic.LoadInt64(&callCount), int64(1))
}

func TestStop(t *testing.T) {
	var callCount int64

	r := Start(context.Background(), 10*time.Millisecond, func() {
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

	r := Start(context.Background(), 50*time.Millisecond, func() {
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

func TestStopCalledTwice(t *testing.T) {
	r := Start(context.Background(), 5*time.Millisecond, func() {})
	time.Sleep(10 * time.Millisecond)

	assert.NotPanics(t, func() {
		r.Stop()
		r.Stop()
	})
}

func TestStartWithNonPositiveInterval(t *testing.T) {
	assert.NotPanics(t, func() {
		Start(context.Background(), 0, func() {}).Stop()
	})

	assert.NotPanics(t, func() {
		Start(context.Background(), -1*time.Millisecond, func() {}).Stop()
	})
}

func TestResetWithNonPositiveInterval(t *testing.T) {
	r := Start(context.Background(), 10*time.Millisecond, func() {})
	defer r.Stop()

	assert.NotPanics(t, func() {
		r.Reset(0)
	})

	assert.NotPanics(t, func() {
		r.Reset(-1 * time.Millisecond)
	})
}

func TestStopCalledConcurrently(t *testing.T) {
	r := Start(context.Background(), 5*time.Millisecond, func() {})
	time.Sleep(10 * time.Millisecond)

	assert.NotPanics(t, func() {
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r.Stop()
			}()
		}
		wg.Wait()
	})
}

func TestParentContextCancellationStopsRoutine(t *testing.T) {
	var callCount int64

	ctx, cancel := context.WithCancel(context.Background())
	r := Start(ctx, 5*time.Millisecond, func() {
		atomic.AddInt64(&callCount, 1)
	})

	time.Sleep(15 * time.Millisecond)
	cancel()
	r.Stop() // Cancelling the parent already stopped the routine; Stop must still return.

	countAtCancel := atomic.LoadInt64(&callCount)
	time.Sleep(20 * time.Millisecond)

	assert.Equal(t, countAtCancel, atomic.LoadInt64(&callCount))
}
