package slidingwindow_test

import (
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/slidingwindow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWindow_EmptyWindow(t *testing.T) {
	window := slidingwindow.New(60, 10)
	now := time.Now().Unix()

	assert.Equal(t, 0, window.Count(now))
	assert.True(t, window.TryRecord(now))
	assert.Equal(t, 1, window.Count(now))
}

func TestWindow_RecordUnderLimit(t *testing.T) {
	window := slidingwindow.New(60, 10)
	now := time.Now().Unix()

	// Add requests under limit
	for range 5 {
		require.True(t, window.TryRecord(now))
	}
	assert.Equal(t, 5, window.Count(now))
}

func TestWindow_RecordAtLimit(t *testing.T) {
	window := slidingwindow.New(60, 3)
	now := time.Now().Unix()

	// Fill to limit
	for range 3 {
		require.True(t, window.TryRecord(now))
	}
	assert.Equal(t, 3, window.Count(now))

	// Next request should be blocked
	assert.False(t, window.TryRecord(now))
	assert.Equal(t, 3, window.Count(now))
}

func TestWindow_ZeroLimit(t *testing.T) {
	window := slidingwindow.New(60, 0)
	now := time.Now().Unix()

	assert.False(t, window.TryRecord(now))
	assert.Equal(t, 0, window.Count(now))
}

func TestWindow_SlidingExpiration(t *testing.T) {
	window := slidingwindow.New(10, 100)
	baseTime := time.Now().Unix()

	// Add requests at different times
	for range 3 {
		window.TryRecord(baseTime) // at t=0
	}
	for range 2 {
		window.TryRecord(baseTime + 5) // at t=5
	}

	// All requests visible at t=5
	assert.Equal(t, 5, window.Count(baseTime+5))

	// Only t=5 requests remain at t=12 (t=0 requests expired)
	assert.Equal(t, 2, window.Count(baseTime+12))

	// All expired at t=16
	assert.Equal(t, 0, window.Count(baseTime+16))
}

func TestWindow_ExactBoundary(t *testing.T) {
	window := slidingwindow.New(10, 100)
	baseTime := time.Now().Unix()

	window.TryRecord(baseTime)

	// Still in window just before boundary
	assert.Equal(t, 1, window.Count(baseTime+9))

	// Expired at exact boundary
	assert.Equal(t, 0, window.Count(baseTime+10))
}

func TestWindow_CountIsIdempotent(t *testing.T) {
	window := slidingwindow.New(60, 10)
	now := time.Now().Unix()

	for range 5 {
		window.TryRecord(now)
	}

	// Multiple counts should return same value
	assert.Equal(t, 5, window.Count(now))
	assert.Equal(t, 5, window.Count(now))
	assert.Equal(t, 5, window.Count(now))
}

func TestWindow_ConcurrentAccess(t *testing.T) {
	window := slidingwindow.New(60, 100)
	now := time.Now().Unix()

	const goroutines = 10
	const requestsPerGoroutine = 10
	results := make(chan bool, goroutines*requestsPerGoroutine)

	// Launch concurrent recordings
	for range goroutines {
		go func() {
			for range requestsPerGoroutine {
				results <- window.TryRecord(now)
			}
		}()
	}

	// Collect results
	successful := 0
	for range goroutines * requestsPerGoroutine {
		if <-results {
			successful++
		}
	}

	// All 100 should succeed (exactly at limit)
	assert.Equal(t, 100, successful)
	assert.Equal(t, 100, window.Count(now))
}

func TestWindow_ConcurrentExceedingLimit(t *testing.T) {
	window := slidingwindow.New(60, 50)
	now := time.Now().Unix()

	const totalRequests = 100
	results := make(chan bool, totalRequests)

	// 100 concurrent requests against limit of 50
	for range 10 {
		go func() {
			for range 10 {
				results <- window.TryRecord(now)
			}
		}()
	}

	successful := 0
	for range totalRequests {
		if <-results {
			successful++
		}
	}

	// Exactly 50 should succeed, rest blocked
	assert.Equal(t, 50, successful)
	assert.Equal(t, 50, window.Count(now))
}
