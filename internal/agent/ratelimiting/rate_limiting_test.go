package ratelimiting

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMillisecondsToMinutes(t *testing.T) {
	testCases := []struct {
		name     string
		ms       int
		expected int
	}{
		{"1 minute", 60000, 1},
		{"5 minutes", 300000, 5},
		{"10 minutes", 600000, 10},
		{"30 minutes", 1800000, 30},
		{"1 hour", 3600000, 60},
		{"2 hours", 7200000, 120},
		{"0 ms", 0, 0},
		{"500 ms", 500, 0}, // Less than a minute rounds down
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := millisecondsToMinutes(tc.ms)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetOrCreateCounts(t *testing.T) {
	m := make(map[string]*entityCounts)

	// Empty key returns nil
	counts := getOrCreateCounts(m, "")
	assert.Nil(t, counts)
	assert.Empty(t, m)

	// Creates new entry
	counts = getOrCreateCounts(m, "user1")
	require.NotNil(t, counts)
	assert.Empty(t, counts.requestTimestamps)
	assert.Contains(t, m, "user1")

	// Returns existing entry
	counts.requestTimestamps = append(counts.requestTimestamps, 100)
	counts2 := getOrCreateCounts(m, "user1")
	assert.Equal(t, counts, counts2)
	assert.Equal(t, 1, len(counts2.requestTimestamps))
}

func TestCleanOldTimestamps(t *testing.T) {
	t.Run("removes old timestamps", func(t *testing.T) {
		counts := &entityCounts{
			requestTimestamps: []int64{100, 200, 300, 400, 500},
		}

		cleanOldTimestamps(counts, 350)

		assert.Equal(t, []int64{400, 500}, counts.requestTimestamps)
	})

	t.Run("removes all if all old", func(t *testing.T) {
		counts := &entityCounts{
			requestTimestamps: []int64{100, 200, 300},
		}

		cleanOldTimestamps(counts, 500)

		assert.Empty(t, counts.requestTimestamps)
	})

	t.Run("keeps all if none old", func(t *testing.T) {
		counts := &entityCounts{
			requestTimestamps: []int64{100, 200, 300},
		}

		cleanOldTimestamps(counts, 50)

		assert.Equal(t, []int64{100, 200, 300}, counts.requestTimestamps)
	})

	t.Run("handles empty slice", func(t *testing.T) {
		counts := &entityCounts{
			requestTimestamps: []int64{},
		}

		cleanOldTimestamps(counts, 100)

		assert.Empty(t, counts.requestTimestamps)
	})
}

func TestUpdateCounts(t *testing.T) {
	rl := New()
	key := endpointKey{Method: "GET", Route: "/api/test"}
	rl.rateLimitingMap[key] = &endpointData{
		Config: rateLimitConfig{
			MaxRequests:         10,
			WindowSizeInMinutes: 5,
		},
		UserCounts: make(map[string]*entityCounts),
		IPCounts:   make(map[string]*entityCounts),
	}

	// Test updating counts for user and IP
	rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1")

	value := rl.rateLimitingMap[key]
	require.NotNil(t, value)
	assert.Equal(t, 1, len(value.UserCounts["user1"].requestTimestamps))
	assert.Equal(t, 1, len(value.IPCounts["192.168.1.1"].requestTimestamps))

	// Update again
	rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1")

	value = rl.rateLimitingMap[key]
	assert.Equal(t, 2, len(value.UserCounts["user1"].requestTimestamps))
	assert.Equal(t, 2, len(value.IPCounts["192.168.1.1"].requestTimestamps))

	// Test with non-existent route (should do nothing)
	rl.UpdateCounts("POST", "/api/other", "user1", "192.168.1.1")
}

func TestUpdateCounts_CleansOldTimestamps(t *testing.T) {
	rl := New()
	key := endpointKey{Method: "GET", Route: "/api/test"}
	rl.rateLimitingMap[key] = &endpointData{
		Config: rateLimitConfig{
			MaxRequests:         10,
			WindowSizeInMinutes: 5,
		},
		UserCounts: make(map[string]*entityCounts),
		IPCounts:   make(map[string]*entityCounts),
	}

	// Add some old timestamps manually
	now := time.Now().Unix()
	old := now - 600 // 10 minutes ago (outside 5 minute window)
	rl.rateLimitingMap[key].UserCounts["user1"] = &entityCounts{
		requestTimestamps: []int64{old, old + 10, old + 20},
	}

	// Update should clean old timestamps
	rl.UpdateCounts("GET", "/api/test", "user1", "")

	counts := rl.rateLimitingMap[key].UserCounts["user1"]
	// Only the new timestamp should remain (old ones cleaned)
	assert.Equal(t, 1, len(counts.requestTimestamps))
	assert.GreaterOrEqual(t, counts.requestTimestamps[0], now)
}

func TestGetStatus(t *testing.T) {
	t.Run("non-existent route returns no block", func(t *testing.T) {
		rl := New()

		status := rl.GetStatus("POST", "/api/other", "user1", "192.168.1.1")

		assert.NotNil(t, status)
		assert.False(t, status.Block)
		assert.Empty(t, status.Trigger)
	})

	t.Run("user below threshold not blocked", func(t *testing.T) {
		rl := New()
		key := endpointKey{Method: "GET", Route: "/api/test"}
		rl.rateLimitingMap[key] = &endpointData{
			Config:     rateLimitConfig{MaxRequests: 3, WindowSizeInMinutes: 5},
			UserCounts: make(map[string]*entityCounts),
			IPCounts:   make(map[string]*entityCounts),
		}

		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1")
		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1")

		status := rl.GetStatus("GET", "/api/test", "user1", "192.168.1.1")

		assert.False(t, status.Block)
	})

	t.Run("user at threshold blocked", func(t *testing.T) {
		rl := New()
		key := endpointKey{Method: "GET", Route: "/api/test"}
		rl.rateLimitingMap[key] = &endpointData{
			Config:     rateLimitConfig{MaxRequests: 3, WindowSizeInMinutes: 5},
			UserCounts: make(map[string]*entityCounts),
			IPCounts:   make(map[string]*entityCounts),
		}

		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1")
		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1")
		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1")

		status := rl.GetStatus("GET", "/api/test", "user1", "192.168.1.1")

		assert.True(t, status.Block)
		assert.Equal(t, "user", status.Trigger)
	})

	t.Run("IP blocked when no user provided", func(t *testing.T) {
		rl := New()
		key := endpointKey{Method: "GET", Route: "/api/test"}
		rl.rateLimitingMap[key] = &endpointData{
			Config:     rateLimitConfig{MaxRequests: 3, WindowSizeInMinutes: 5},
			UserCounts: make(map[string]*entityCounts),
			IPCounts:   make(map[string]*entityCounts),
		}

		rl.UpdateCounts("GET", "/api/test", "", "192.168.1.1")
		rl.UpdateCounts("GET", "/api/test", "", "192.168.1.1")
		rl.UpdateCounts("GET", "/api/test", "", "192.168.1.1")

		status := rl.GetStatus("GET", "/api/test", "", "192.168.1.1")

		assert.True(t, status.Block)
		assert.Equal(t, "ip", status.Trigger)
	})

	t.Run("IP below threshold not blocked", func(t *testing.T) {
		rl := New()
		key := endpointKey{Method: "POST", Route: "/api/other"}
		rl.rateLimitingMap[key] = &endpointData{
			Config:     rateLimitConfig{MaxRequests: 5, WindowSizeInMinutes: 5},
			UserCounts: make(map[string]*entityCounts),
			IPCounts:   make(map[string]*entityCounts),
		}

		rl.UpdateCounts("POST", "/api/other", "", "192.168.1.2")
		rl.UpdateCounts("POST", "/api/other", "", "192.168.1.2")

		status := rl.GetStatus("POST", "/api/other", "", "192.168.1.2")

		assert.False(t, status.Block)
	})
}

func TestGetStatus_CleansOldTimestamps(t *testing.T) {
	rl := New()
	key := endpointKey{Method: "GET", Route: "/api/test"}
	rl.rateLimitingMap[key] = &endpointData{
		Config:     rateLimitConfig{MaxRequests: 3, WindowSizeInMinutes: 5},
		UserCounts: make(map[string]*entityCounts),
		IPCounts:   make(map[string]*entityCounts),
	}

	// Add old and new timestamps
	now := time.Now().Unix()
	old := now - 600 // 10 minutes ago
	rl.rateLimitingMap[key].UserCounts["user1"] = &entityCounts{
		requestTimestamps: []int64{old, old + 10, now - 60, now - 30},
	}

	status := rl.GetStatus("GET", "/api/test", "user1", "")

	// Should have cleaned old timestamps
	counts := rl.rateLimitingMap[key].UserCounts["user1"]
	assert.Equal(t, 2, len(counts.requestTimestamps)) // Only recent ones remain
	assert.False(t, status.Block)                     // Below threshold
}

func TestCleanupInactive(t *testing.T) {
	rl := New()
	key := endpointKey{Method: "GET", Route: "/api/test"}
	rl.rateLimitingMap[key] = &endpointData{
		Config:     rateLimitConfig{MaxRequests: 10, WindowSizeInMinutes: 5},
		UserCounts: make(map[string]*entityCounts),
		IPCounts:   make(map[string]*entityCounts),
	}

	now := time.Now().Unix()
	veryOld := now - int64(inactivityThreshold.Seconds()) - 100
	recent := now - 60

	// Add various states
	rl.rateLimitingMap[key].UserCounts["inactive"] = &entityCounts{
		requestTimestamps: []int64{veryOld},
	}
	rl.rateLimitingMap[key].UserCounts["active"] = &entityCounts{
		requestTimestamps: []int64{recent},
	}
	rl.rateLimitingMap[key].UserCounts["empty"] = &entityCounts{
		requestTimestamps: []int64{},
	}

	rl.cleanupInactive()

	// Inactive and empty should be removed
	assert.NotContains(t, rl.rateLimitingMap[key].UserCounts, "inactive")
	assert.NotContains(t, rl.rateLimitingMap[key].UserCounts, "empty")
	// Active should remain
	assert.Contains(t, rl.rateLimitingMap[key].UserCounts, "active")
}

func TestGetStatus_Concurrent(t *testing.T) {
	rl := New()
	key := endpointKey{Method: "GET", Route: "/api/test"}
	rl.rateLimitingMap[key] = &endpointData{
		Config: rateLimitConfig{
			MaxRequests:         100,
			WindowSizeInMinutes: 5,
		},
		UserCounts: make(map[string]*entityCounts),
		IPCounts:   make(map[string]*entityCounts),
	}

	// Concurrent updates and reads
	wg := sync.WaitGroup{}
	wg.Add(10)
	for range 10 {
		go func() {
			for range 10 {
				rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1")
				rl.GetStatus("GET", "/api/test", "user1", "192.168.1.1")
			}
			wg.Done()
		}()
	}

	wg.Wait()

	value := rl.rateLimitingMap[key]
	assert.Equal(t, 100, len(value.UserCounts["user1"].requestTimestamps))
}
