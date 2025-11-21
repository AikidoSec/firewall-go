package ratelimiting

import (
	"sync"
	"testing"

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

func TestIncrementRateLimitingCounts(t *testing.T) {
	m := make(map[string]*entityCounts)

	incrementRateLimitingCounts(m, "")
	assert.Empty(t, m, "empty key should not create entry")

	incrementRateLimitingCounts(m, "user1")
	incrementRateLimitingCounts(m, "user1")
	assert.Equal(t, 2, m["user1"].TotalNumberOfRequests)

	incrementRateLimitingCounts(m, "user2")
	assert.Equal(t, 1, m["user2"].TotalNumberOfRequests)
	assert.Equal(t, 2, m["user1"].TotalNumberOfRequests, "user1 unchanged")
}

func TestIsRateLimitingThresholdExceeded(t *testing.T) {
	config := rateLimitConfig{MaxRequests: 5, WindowSizeInMinutes: 10}

	tests := []struct {
		name     string
		counts   map[string]*entityCounts
		key      string
		expected bool
	}{
		{"non-existent key", map[string]*entityCounts{}, "user1", false},
		{"below threshold", map[string]*entityCounts{"user1": {TotalNumberOfRequests: 4}}, "user1", false},
		{"at threshold", map[string]*entityCounts{"user1": {TotalNumberOfRequests: 5}}, "user1", true},
		{"above threshold", map[string]*entityCounts{"user1": {TotalNumberOfRequests: 6}}, "user1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRateLimitingThresholdExceeded(&config, tt.counts, tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUpdateCounts(t *testing.T) {
	rl := New()
	// Setup: Add a route to the rate limiting map
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
	assert.Equal(t, 1, value.UserCounts["user1"].TotalNumberOfRequests)
	assert.Equal(t, 1, value.IPCounts["192.168.1.1"].TotalNumberOfRequests)

	// Update again
	rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1")

	value = rl.rateLimitingMap[key]
	assert.Equal(t, 2, value.UserCounts["user1"].TotalNumberOfRequests)
	assert.Equal(t, 2, value.IPCounts["192.168.1.1"].TotalNumberOfRequests)

	// Test with non-existent route (should do nothing)
	rl.UpdateCounts("POST", "/api/other", "user1", "192.168.1.1")
}

func TestAdvanceQueuesForMap(t *testing.T) {
	config := rateLimitConfig{MaxRequests: 10, WindowSizeInMinutes: 3}

	t.Run("pops when window is full", func(t *testing.T) {
		counts := &entityCounts{
			TotalNumberOfRequests:     15,
			NumberOfRequestsPerWindow: queue{items: []int{5, 4, 6}},
		}
		m := map[string]*entityCounts{"user1": counts}

		advanceQueuesForMap(&config, m)

		assert.Equal(t, 10, counts.TotalNumberOfRequests)
		assert.Equal(t, 3, counts.NumberOfRequestsPerWindow.Length())
	})

	t.Run("pushes when window not full", func(t *testing.T) {
		counts := &entityCounts{
			TotalNumberOfRequests:     5,
			NumberOfRequestsPerWindow: queue{items: []int{3, 2}},
		}
		m := map[string]*entityCounts{"user1": counts}

		advanceQueuesForMap(&config, m)

		assert.Equal(t, 5, counts.TotalNumberOfRequests)
		assert.Equal(t, 3, counts.NumberOfRequestsPerWindow.Length())
	})
}

func TestAdvanceQueues(t *testing.T) {
	rl := New()
	key1 := endpointKey{Method: "GET", Route: "/api/test1"}
	key2 := endpointKey{Method: "POST", Route: "/api/test2"}

	rl.rateLimitingMap[key1] = &endpointData{
		Config: rateLimitConfig{
			MaxRequests:         10,
			WindowSizeInMinutes: 2,
		},
		UserCounts: map[string]*entityCounts{
			"user1": {
				TotalNumberOfRequests:     5,
				NumberOfRequestsPerWindow: queue{items: []int{2, 3}},
			},
		},
		IPCounts: make(map[string]*entityCounts),
	}

	rl.rateLimitingMap[key2] = &endpointData{
		Config: rateLimitConfig{
			MaxRequests:         10,
			WindowSizeInMinutes: 2,
		},
		UserCounts: make(map[string]*entityCounts),
		IPCounts: map[string]*entityCounts{
			"192.168.1.1": {
				TotalNumberOfRequests:     7,
				NumberOfRequestsPerWindow: queue{items: []int{3, 4}},
			},
		},
	}

	rl.advanceQueues()

	value1 := rl.rateLimitingMap[key1]
	value2 := rl.rateLimitingMap[key2]

	// Check user counts for key1
	assert.Equal(t, 3, value1.UserCounts["user1"].TotalNumberOfRequests) // 5 - 2 = 3
	assert.Equal(t, 2, value1.UserCounts["user1"].NumberOfRequestsPerWindow.Length())

	// Check IP counts for key2
	assert.Equal(t, 4, value2.IPCounts["192.168.1.1"].TotalNumberOfRequests) // 7 - 3 = 4
	assert.Equal(t, 2, value2.IPCounts["192.168.1.1"].NumberOfRequestsPerWindow.Length())
}

func TestAdvanceQueuesForMap_EdgeCase(t *testing.T) {
	config := rateLimitConfig{
		MaxRequests:         10,
		WindowSizeInMinutes: 2,
	}

	m := make(map[string]*entityCounts)
	counts := &entityCounts{
		TotalNumberOfRequests:     5,
		NumberOfRequestsPerWindow: queue{},
	}
	m["user1"] = counts

	// Setup queue with more requests in popped item than total (edge case)
	counts.NumberOfRequestsPerWindow.Push(10) // This will be popped
	counts.TotalNumberOfRequests = 5          // Less than what we'll pop

	advanceQueuesForMap(&config, m)

	// Should handle gracefully - total should not go negative
	assert.GreaterOrEqual(t, counts.TotalNumberOfRequests, 0)
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
	assert.Equal(t, 100, value.UserCounts["user1"].TotalNumberOfRequests)
}
