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

func TestShouldRateLimitRequest(t *testing.T) {
	t.Run("non-existent route returns no block", func(t *testing.T) {
		rl := New()

		status := rl.ShouldRateLimitRequest("POST", "/api/other", "user1", "192.168.1.1")

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

		_ = rl.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")
		status := rl.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")

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

		_ = rl.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")
		_ = rl.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")

		status := rl.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")

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

		_ = rl.ShouldRateLimitRequest("GET", "/api/test", "", "192.168.1.1")
		_ = rl.ShouldRateLimitRequest("GET", "/api/test", "", "192.168.1.1")

		status := rl.ShouldRateLimitRequest("GET", "/api/test", "", "192.168.1.1")

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

		_ = rl.ShouldRateLimitRequest("POST", "/api/other", "", "192.168.1.2")

		status := rl.ShouldRateLimitRequest("POST", "/api/other", "", "192.168.1.2")

		assert.False(t, status.Block)
	})
}

func TestShouldRateLimitRequest_CleansOldTimestamps(t *testing.T) {
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

	status := rl.ShouldRateLimitRequest("GET", "/api/test", "user1", "")

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

func TestShouldRateLimitRequest_Concurrent(t *testing.T) {
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
				rl.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")
			}
			wg.Done()
		}()
	}

	wg.Wait()

	value := rl.rateLimitingMap[key]
	assert.Equal(t, 100, len(value.UserCounts["user1"].requestTimestamps))
}

func TestUpdateConfig(t *testing.T) {
	makeEndpointConfig := func(method, route string, enabled bool, maxRequests, windowSizeInMS int) EndpointConfig {
		return EndpointConfig{
			Method: method,
			Route:  route,
			RateLimiting: struct {
				Enabled        bool
				MaxRequests    int
				WindowSizeInMS int
			}{
				Enabled:        enabled,
				MaxRequests:    maxRequests,
				WindowSizeInMS: windowSizeInMS,
			},
		}
	}

	t.Run("adds new endpoints", func(t *testing.T) {
		rl := New()

		endpoints := []EndpointConfig{
			makeEndpointConfig("GET", "/api/test", true, 10, 300000),
			makeEndpointConfig("POST", "/api/create", true, 5, 600000),
		}

		rl.UpdateConfig(endpoints)

		key1 := endpointKey{Method: "GET", Route: "/api/test"}
		value1 := rl.rateLimitingMap[key1]
		require.NotNil(t, value1)
		assert.Equal(t, 10, value1.Config.MaxRequests)
		assert.Equal(t, 5, value1.Config.WindowSizeInMinutes)
		assert.NotNil(t, value1.UserCounts)
		assert.NotNil(t, value1.IPCounts)

		key2 := endpointKey{Method: "POST", Route: "/api/create"}
		value2 := rl.rateLimitingMap[key2]
		require.NotNil(t, value2)
		assert.Equal(t, 5, value2.Config.MaxRequests)
		assert.Equal(t, 10, value2.Config.WindowSizeInMinutes)
	})

	t.Run("preserves data when config unchanged", func(t *testing.T) {
		rl := New()

		endpoints := []EndpointConfig{
			makeEndpointConfig("GET", "/api/test", true, 10, 300000),
		}

		rl.UpdateConfig(endpoints)

		key := endpointKey{Method: "GET", Route: "/api/test"}
		originalValue := rl.rateLimitingMap[key]

		// Add some data
		originalValue.UserCounts["user1"] = &entityCounts{requestTimestamps: []int64{100, 200, 300, 400, 500}}
		originalValue.IPCounts["192.168.1.1"] = &entityCounts{requestTimestamps: []int64{100, 200, 300}}

		// Update with same config
		rl.UpdateConfig(endpoints)

		updatedValue := rl.rateLimitingMap[key]
		assert.Equal(t, originalValue, updatedValue, "should be same instance")
		assert.Equal(t, 5, len(updatedValue.UserCounts["user1"].requestTimestamps))
		assert.Equal(t, 3, len(updatedValue.IPCounts["192.168.1.1"].requestTimestamps))
	})

	t.Run("resets data when config changed", func(t *testing.T) {
		rl := New()

		initialEndpoints := []EndpointConfig{
			makeEndpointConfig("GET", "/api/test", true, 10, 300000),
		}
		rl.UpdateConfig(initialEndpoints)

		key := endpointKey{Method: "GET", Route: "/api/test"}
		rl.rateLimitingMap[key].UserCounts["user1"] = &entityCounts{requestTimestamps: []int64{100, 200, 300, 400, 500}}

		// Update with different config
		changedEndpoints := []EndpointConfig{
			makeEndpointConfig("GET", "/api/test", true, 20, 300000),
		}
		rl.UpdateConfig(changedEndpoints)

		value := rl.rateLimitingMap[key]
		require.NotNil(t, value)
		assert.Equal(t, 20, value.Config.MaxRequests)
		assert.Empty(t, value.UserCounts)
		assert.Empty(t, value.IPCounts)
	})

	t.Run("ignores disabled endpoints", func(t *testing.T) {
		rl := New()

		endpoints := []EndpointConfig{
			makeEndpointConfig("GET", "/api/test", false, 10, 300000),
		}

		rl.UpdateConfig(endpoints)

		key := endpointKey{Method: "GET", Route: "/api/test"}
		assert.Nil(t, rl.rateLimitingMap[key])
	})

	t.Run("removes disabled endpoints", func(t *testing.T) {
		rl := New()

		// First add enabled endpoint
		enabledEndpoints := []EndpointConfig{
			makeEndpointConfig("GET", "/api/test", true, 10, 300000),
		}
		rl.UpdateConfig(enabledEndpoints)

		key := endpointKey{Method: "GET", Route: "/api/test"}
		require.NotNil(t, rl.rateLimitingMap[key])

		// Now disable it
		disabledEndpoints := []EndpointConfig{
			makeEndpointConfig("GET", "/api/test", false, 10, 300000),
		}
		rl.UpdateConfig(disabledEndpoints)

		assert.Nil(t, rl.rateLimitingMap[key])
	})

	t.Run("ignores invalid window sizes", func(t *testing.T) {
		tests := []struct {
			name           string
			windowSizeInMS int
		}{
			{"too small", 1000},
			{"too large", 4000000},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				rl := New()

				endpoints := []EndpointConfig{
					makeEndpointConfig("GET", "/api/test", true, 10, tt.windowSizeInMS),
				}

				rl.UpdateConfig(endpoints)

				key := endpointKey{Method: "GET", Route: "/api/test"}
				assert.Nil(t, rl.rateLimitingMap[key])
			})
		}
	})

	t.Run("removes endpoints not in new config", func(t *testing.T) {
		rl := New()

		// Add two endpoints
		initialEndpoints := []EndpointConfig{
			makeEndpointConfig("GET", "/api/test", true, 10, 300000),
			makeEndpointConfig("POST", "/api/create", true, 5, 600000),
		}
		rl.UpdateConfig(initialEndpoints)

		key1 := endpointKey{Method: "GET", Route: "/api/test"}
		key2 := endpointKey{Method: "POST", Route: "/api/create"}
		require.NotNil(t, rl.rateLimitingMap[key1])
		require.NotNil(t, rl.rateLimitingMap[key2])

		// Update with only one endpoint
		updatedEndpoints := []EndpointConfig{
			makeEndpointConfig("POST", "/api/create", true, 5, 600000),
		}
		rl.UpdateConfig(updatedEndpoints)

		assert.Nil(t, rl.rateLimitingMap[key1])
		assert.NotNil(t, rl.rateLimitingMap[key2])
	})

	t.Run("removes all endpoints when config empty", func(t *testing.T) {
		rl := New()

		// Add an endpoint
		endpoints := []EndpointConfig{
			makeEndpointConfig("GET", "/api/test", true, 10, 300000),
		}
		rl.UpdateConfig(endpoints)
		require.NotEmpty(t, rl.rateLimitingMap)

		// Update with empty config
		rl.UpdateConfig([]EndpointConfig{})

		assert.Empty(t, rl.rateLimitingMap)
	})
}
