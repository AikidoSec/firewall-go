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
		UserCounts:  make(map[string]*entityCounts),
		GroupCounts: make(map[string]*entityCounts),
		IPCounts:    make(map[string]*entityCounts),
	}

	// Test updating counts for user and IP
	rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "")

	value := rl.rateLimitingMap[key]
	require.NotNil(t, value)
	assert.Equal(t, 1, value.UserCounts["user1"].TotalNumberOfRequests)
	assert.Equal(t, 1, value.IPCounts["192.168.1.1"].TotalNumberOfRequests)

	// Update again
	rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "")

	value = rl.rateLimitingMap[key]
	assert.Equal(t, 2, value.UserCounts["user1"].TotalNumberOfRequests)
	assert.Equal(t, 2, value.IPCounts["192.168.1.1"].TotalNumberOfRequests)

	// Test with non-existent route (should do nothing)
	rl.UpdateCounts("POST", "/api/other", "user1", "192.168.1.1", "")

	// Test updating counts with group
	rl.UpdateCounts("GET", "/api/test", "user2", "192.168.1.2", "group1")

	value = rl.rateLimitingMap[key]
	assert.Equal(t, 1, value.UserCounts["user2"].TotalNumberOfRequests)
	assert.Equal(t, 1, value.IPCounts["192.168.1.2"].TotalNumberOfRequests)
	assert.Equal(t, 1, value.GroupCounts["group1"].TotalNumberOfRequests)
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
		GroupCounts: make(map[string]*entityCounts),
		IPCounts:    make(map[string]*entityCounts),
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

		status := rl.GetStatus("POST", "/api/other", "user1", "192.168.1.1", "")

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

		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "")
		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "")

		status := rl.GetStatus("GET", "/api/test", "user1", "192.168.1.1", "")

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

		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "")
		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "")
		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "")

		status := rl.GetStatus("GET", "/api/test", "user1", "192.168.1.1", "")

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

		rl.UpdateCounts("GET", "/api/test", "", "192.168.1.1", "")
		rl.UpdateCounts("GET", "/api/test", "", "192.168.1.1", "")
		rl.UpdateCounts("GET", "/api/test", "", "192.168.1.1", "")

		status := rl.GetStatus("GET", "/api/test", "", "192.168.1.1", "")

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

		rl.UpdateCounts("POST", "/api/other", "", "192.168.1.2", "")
		rl.UpdateCounts("POST", "/api/other", "", "192.168.1.2", "")

		status := rl.GetStatus("POST", "/api/other", "", "192.168.1.2", "")

		assert.False(t, status.Block)
	})

	t.Run("group at threshold blocked", func(t *testing.T) {
		rl := New()
		key := endpointKey{Method: "GET", Route: "/api/test"}
		rl.rateLimitingMap[key] = &endpointData{
			Config:      rateLimitConfig{MaxRequests: 3, WindowSizeInMinutes: 5},
			UserCounts:  make(map[string]*entityCounts),
			GroupCounts: make(map[string]*entityCounts),
			IPCounts:    make(map[string]*entityCounts),
		}

		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "group1")
		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "group1")
		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "group1")

		status := rl.GetStatus("GET", "/api/test", "user1", "192.168.1.1", "group1")

		assert.True(t, status.Block)
		assert.Equal(t, "group", status.Trigger)
	})

	t.Run("group below threshold not blocked", func(t *testing.T) {
		rl := New()
		key := endpointKey{Method: "POST", Route: "/api/other"}
		rl.rateLimitingMap[key] = &endpointData{
			Config:      rateLimitConfig{MaxRequests: 5, WindowSizeInMinutes: 5},
			UserCounts:  make(map[string]*entityCounts),
			GroupCounts: make(map[string]*entityCounts),
			IPCounts:    make(map[string]*entityCounts),
		}

		rl.UpdateCounts("POST", "/api/other", "user1", "192.168.1.2", "group1")
		rl.UpdateCounts("POST", "/api/other", "user1", "192.168.1.2", "group1")

		status := rl.GetStatus("POST", "/api/other", "user1", "192.168.1.2", "group1")

		assert.False(t, status.Block)
	})

	t.Run("group takes precedence over user", func(t *testing.T) {
		rl := New()
		key := endpointKey{Method: "GET", Route: "/api/test"}
		rl.rateLimitingMap[key] = &endpointData{
			Config:      rateLimitConfig{MaxRequests: 3, WindowSizeInMinutes: 5},
			UserCounts:  make(map[string]*entityCounts),
			GroupCounts: make(map[string]*entityCounts),
			IPCounts:    make(map[string]*entityCounts),
		}

		// Update user counts but not group counts
		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "group1")
		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "group1")
		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "group1")

		// Should block by group, not user
		status := rl.GetStatus("GET", "/api/test", "user1", "192.168.1.1", "group1")
		assert.True(t, status.Block)
		assert.Equal(t, "group", status.Trigger)
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
		UserCounts:  make(map[string]*entityCounts),
		GroupCounts: make(map[string]*entityCounts),
		IPCounts:    make(map[string]*entityCounts),
	}

	// Concurrent updates and reads
	wg := sync.WaitGroup{}
	wg.Add(10)
	for range 10 {
		go func() {
			for range 10 {
				rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "")
				rl.GetStatus("GET", "/api/test", "user1", "192.168.1.1", "")
			}
			wg.Done()
		}()
	}

	wg.Wait()

	value := rl.rateLimitingMap[key]
	assert.Equal(t, 100, value.UserCounts["user1"].TotalNumberOfRequests)
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
		assert.NotNil(t, value1.GroupCounts)
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
		originalValue.UserCounts["user1"] = &entityCounts{TotalNumberOfRequests: 5}
		originalValue.IPCounts["192.168.1.1"] = &entityCounts{TotalNumberOfRequests: 3}

		// Update with same config
		rl.UpdateConfig(endpoints)

		updatedValue := rl.rateLimitingMap[key]
		assert.Equal(t, originalValue, updatedValue, "should be same instance")
		assert.Equal(t, 5, updatedValue.UserCounts["user1"].TotalNumberOfRequests)
		assert.Equal(t, 3, updatedValue.IPCounts["192.168.1.1"].TotalNumberOfRequests)
	})

	t.Run("resets data when config changed", func(t *testing.T) {
		rl := New()

		initialEndpoints := []EndpointConfig{
			makeEndpointConfig("GET", "/api/test", true, 10, 300000),
		}
		rl.UpdateConfig(initialEndpoints)

		key := endpointKey{Method: "GET", Route: "/api/test"}
		rl.rateLimitingMap[key].UserCounts["user1"] = &entityCounts{TotalNumberOfRequests: 5}

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

func TestRateLimitingWithWildcards(t *testing.T) {
	t.Run("wildcard route matches multiple specific routes", func(t *testing.T) {
		rl := New()

		// Configure a wildcard endpoint
		endpoints := []EndpointConfig{
			{
				Method: "*",
				Route:  "/api/*",
				RateLimiting: struct {
					Enabled        bool
					MaxRequests    int
					WindowSizeInMS int
				}{
					Enabled:        true,
					MaxRequests:    3,
					WindowSizeInMS: 100000,
				},
			},
		}

		rl.UpdateConfig(endpoints)

		// /api/test should match /api/*
		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "")
		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "")
		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "")

		status := rl.GetStatus("GET", "/api/test", "user1", "192.168.1.1", "")
		assert.True(t, status.Block, "should block after exceeding limit on wildcard route")

		// /api/users/123 should also match /api/*
		rl2 := New()
		rl2.UpdateConfig(endpoints)
		rl2.UpdateCounts("POST", "/api/users/123", "user2", "192.168.1.2", "")
		rl2.UpdateCounts("POST", "/api/users/123", "user2", "192.168.1.2", "")
		rl2.UpdateCounts("POST", "/api/users/123", "user2", "192.168.1.2", "")

		status2 := rl2.GetStatus("POST", "/api/users/123", "user2", "192.168.1.2", "")
		assert.True(t, status2.Block, "should block after exceeding limit on another route matching wildcard")
	})

	t.Run("wildcard route with specific method matches only that method", func(t *testing.T) {
		rl := New()

		// Configure a wildcard endpoint with specific method
		endpoints := []EndpointConfig{
			{
				Method: "POST",
				Route:  "/api/*",
				RateLimiting: struct {
					Enabled        bool
					MaxRequests    int
					WindowSizeInMS int
				}{
					Enabled:        true,
					MaxRequests:    2,
					WindowSizeInMS: 100000,
				},
			},
		}

		rl.UpdateConfig(endpoints)

		// POST requests should match
		rl.UpdateCounts("POST", "/api/test", "user1", "192.168.1.1", "")
		rl.UpdateCounts("POST", "/api/test", "user1", "192.168.1.1", "")

		status := rl.GetStatus("POST", "/api/test", "user1", "192.168.1.1", "")
		assert.True(t, status.Block, "should block POST requests matching wildcard")

		// GET requests should not match
		rl2 := New()
		rl2.UpdateConfig(endpoints)
		rl2.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "")
		rl2.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "")
		rl2.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "")

		status2 := rl2.GetStatus("GET", "/api/test", "user1", "192.168.1.1", "")
		assert.False(t, status2.Block, "should not block GET requests when wildcard is for POST only")
	})

	t.Run("most restrictive rate takes precedence when multiple wildcards match", func(t *testing.T) {
		t.Run("more specific wildcard is more restrictive", func(t *testing.T) {
			rl := New()

			// Configure multiple wildcard endpoints that both match the same route
			// The one with the lowest rate (maxRequests / windowSizeInMS) should win
			endpoints := []EndpointConfig{
				{
					Method: "*",
					Route:  "/api/*",
					RateLimiting: struct {
						Enabled        bool
						MaxRequests    int
						WindowSizeInMS int
					}{
						Enabled:        true,
						MaxRequests:    10,
						WindowSizeInMS: 100000, // Rate: 10/100000 = 0.0001
					},
				},
				{
					Method: "*",
					Route:  "/api/posts/*",
					RateLimiting: struct {
						Enabled        bool
						MaxRequests    int
						WindowSizeInMS int
					}{
						Enabled:        true,
						MaxRequests:    2,
						WindowSizeInMS: 100000, // Rate: 2/100000 = 0.00002 (more restrictive)
					},
				},
			}

			rl.UpdateConfig(endpoints)

			// /api/posts/123 matches both wildcards, but should use the most restrictive one (2 requests)
			rl.UpdateCounts("GET", "/api/posts/123", "user1", "192.168.1.1", "")
			rl.UpdateCounts("GET", "/api/posts/123", "user1", "192.168.1.1", "")

			status := rl.GetStatus("GET", "/api/posts/123", "user1", "192.168.1.1", "")
			assert.True(t, status.Block, "should block based on most restrictive wildcard limit (2 requests)")

			// /api/users/123 only matches /api/*, so should use that limit (10 requests)
			rl2 := New()
			rl2.UpdateConfig(endpoints)
			rl2.UpdateCounts("GET", "/api/users/123", "user1", "192.168.1.1", "")
			rl2.UpdateCounts("GET", "/api/users/123", "user1", "192.168.1.1", "")
			rl2.UpdateCounts("GET", "/api/users/123", "user1", "192.168.1.1", "")

			status2 := rl2.GetStatus("GET", "/api/users/123", "user1", "192.168.1.1", "")
			assert.False(t, status2.Block, "should not block based on wildcard limit (10 requests)")
		})

		t.Run("less specific wildcard is more restrictive", func(t *testing.T) {
			rl := New()

			// Configure wildcards where the less specific one is more restrictive
			endpoints := []EndpointConfig{
				{
					Method: "*",
					Route:  "/api/*",
					RateLimiting: struct {
						Enabled        bool
						MaxRequests    int
						WindowSizeInMS int
					}{
						Enabled:        true,
						MaxRequests:    2,
						WindowSizeInMS: 100000, // Rate: 2/100000 = 0.00002 (more restrictive)
					},
				},
				{
					Method: "*",
					Route:  "/api/posts/*",
					RateLimiting: struct {
						Enabled        bool
						MaxRequests    int
						WindowSizeInMS int
					}{
						Enabled:        true,
						MaxRequests:    10,
						WindowSizeInMS: 100000, // Rate: 10/100000 = 0.0001 (less restrictive)
					},
				},
			}

			rl.UpdateConfig(endpoints)

			// /api/posts/123 matches both wildcards, should use the most restrictive one (/api/* with 2 requests)
			rl.UpdateCounts("GET", "/api/posts/123", "user1", "192.168.1.1", "")
			rl.UpdateCounts("GET", "/api/posts/123", "user1", "192.168.1.1", "")

			status := rl.GetStatus("GET", "/api/posts/123", "user1", "192.168.1.1", "")
			assert.True(t, status.Block, "should block based on most restrictive rate (2 requests from /api/*), not specificity")
		})
	})

	t.Run("exact route takes precedence over wildcard", func(t *testing.T) {
		rl := New()

		// Configure both exact and wildcard endpoints
		endpoints := []EndpointConfig{
			{
				Method: "GET",
				Route:  "/api/test",
				RateLimiting: struct {
					Enabled        bool
					MaxRequests    int
					WindowSizeInMS int
				}{
					Enabled:        true,
					MaxRequests:    2,
					WindowSizeInMS: 100000,
				},
			},
			{
				Method: "*",
				Route:  "/api/*",
				RateLimiting: struct {
					Enabled        bool
					MaxRequests    int
					WindowSizeInMS int
				}{
					Enabled:        true,
					MaxRequests:    10,
					WindowSizeInMS: 100000,
				},
			},
		}

		rl.UpdateConfig(endpoints)

		// /api/test should match the exact route, not the wildcard
		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "")
		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "")

		status := rl.GetStatus("GET", "/api/test", "user1", "192.168.1.1", "")
		assert.True(t, status.Block, "should block based on exact route limit (2 requests), not wildcard")

		// /api/other should match the wildcard
		rl2 := New()
		rl2.UpdateConfig(endpoints)
		rl2.UpdateCounts("GET", "/api/other", "user1", "192.168.1.1", "")
		rl2.UpdateCounts("GET", "/api/other", "user1", "192.168.1.1", "")
		rl2.UpdateCounts("GET", "/api/other", "user1", "192.168.1.1", "")

		status2 := rl2.GetStatus("GET", "/api/other", "user1", "192.168.1.1", "")
		assert.False(t, status2.Block, "should not block based on wildcard limit (10 requests)")
	})

	t.Run("exact method takes precedence over wildcard method for same route", func(t *testing.T) {
		rl := New()

		// Configure both wildcard method and exact method for the same route
		endpoints := []EndpointConfig{
			{
				Method: "*",
				Route:  "/api/test",
				RateLimiting: struct {
					Enabled        bool
					MaxRequests    int
					WindowSizeInMS int
				}{
					Enabled:        true,
					MaxRequests:    10,
					WindowSizeInMS: 100000,
				},
			},
			{
				Method: "GET",
				Route:  "/api/test",
				RateLimiting: struct {
					Enabled        bool
					MaxRequests    int
					WindowSizeInMS int
				}{
					Enabled:        true,
					MaxRequests:    2,
					WindowSizeInMS: 100000,
				},
			},
		}

		rl.UpdateConfig(endpoints)

		// GET /api/test should match the exact method (GET), not the wildcard method (*)
		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "")
		rl.UpdateCounts("GET", "/api/test", "user1", "192.168.1.1", "")

		status := rl.GetStatus("GET", "/api/test", "user1", "192.168.1.1", "")
		assert.True(t, status.Block, "should block based on exact method limit (2 requests), not wildcard method")

		// POST /api/test should match the wildcard method (*)
		rl2 := New()
		rl2.UpdateConfig(endpoints)
		rl2.UpdateCounts("POST", "/api/test", "user1", "192.168.1.1", "")
		rl2.UpdateCounts("POST", "/api/test", "user1", "192.168.1.1", "")
		rl2.UpdateCounts("POST", "/api/test", "user1", "192.168.1.1", "")

		status2 := rl2.GetStatus("POST", "/api/test", "user1", "192.168.1.1", "")
		assert.False(t, status2.Block, "should not block based on wildcard method limit (10 requests)")
	})

}
