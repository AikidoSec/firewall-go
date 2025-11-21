package ratelimiting

import (
	"sync"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/slidingwindow"
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
			Config: rateLimitConfig{MaxRequests: 3, WindowSizeInMinutes: 5},
			Counts: make(map[entityKey]*slidingwindow.Window),
		}

		_ = rl.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")
		status := rl.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")

		assert.False(t, status.Block)
	})

	t.Run("user at threshold blocked", func(t *testing.T) {
		rl := New()
		key := endpointKey{Method: "GET", Route: "/api/test"}
		rl.rateLimitingMap[key] = &endpointData{
			Config: rateLimitConfig{MaxRequests: 3, WindowSizeInMinutes: 5},
			Counts: make(map[entityKey]*slidingwindow.Window),
		}

		_ = rl.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")
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
			Config: rateLimitConfig{MaxRequests: 3, WindowSizeInMinutes: 5},
			Counts: make(map[entityKey]*slidingwindow.Window),
		}

		_ = rl.ShouldRateLimitRequest("GET", "/api/test", "", "192.168.1.1")
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
			Config: rateLimitConfig{MaxRequests: 5, WindowSizeInMinutes: 5},
			Counts: make(map[entityKey]*slidingwindow.Window),
		}

		_ = rl.ShouldRateLimitRequest("POST", "/api/other", "", "192.168.1.2")

		status := rl.ShouldRateLimitRequest("POST", "/api/other", "", "192.168.1.2")

		assert.False(t, status.Block)
	})
}

func TestCleanupInactive(t *testing.T) {
	rl := New()
	key := endpointKey{Method: "GET", Route: "/api/test"}
	rl.rateLimitingMap[key] = &endpointData{
		Config: rateLimitConfig{MaxRequests: 10, WindowSizeInMinutes: 5},
		Counts: make(map[entityKey]*slidingwindow.Window),
	}

	now := time.Now().Unix()
	veryOld := now - int64(5*60) - 100
	recent := now - 60

	inactiveWindow := slidingwindow.New(5*60, 10)
	inactiveWindow.TryRecord(veryOld)

	activeWindow := slidingwindow.New(5*60, 10)
	activeWindow.TryRecord(recent)

	emptyWindow := slidingwindow.New(5*60, 10)

	// Add various states
	rl.rateLimitingMap[key].Counts[entityKey{Value: "inactive"}] = inactiveWindow
	rl.rateLimitingMap[key].Counts[entityKey{Value: "active"}] = activeWindow
	rl.rateLimitingMap[key].Counts[entityKey{Value: "empty"}] = emptyWindow

	rl.cleanupInactive()

	// Inactive and empty should be removed
	assert.NotContains(t, rl.rateLimitingMap[key].Counts, entityKey{Value: "inactive"})
	assert.NotContains(t, rl.rateLimitingMap[key].Counts, entityKey{Value: "empty"})
	// Active should remain
	assert.Contains(t, rl.rateLimitingMap[key].Counts, entityKey{Value: "active"})
}

func TestShouldRateLimitRequest_Concurrent(t *testing.T) {
	rl := New()
	key := endpointKey{Method: "GET", Route: "/api/test"}
	rl.rateLimitingMap[key] = &endpointData{
		Config: rateLimitConfig{
			MaxRequests:         100,
			WindowSizeInMinutes: 5,
		},
		Counts: make(map[entityKey]*slidingwindow.Window),
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
	assert.Equal(t, 100, value.Counts[entityKey{Kind: entityKindUser, Value: "user1"}].Count(time.Now().Unix()))
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
		assert.NotNil(t, value1.Counts)

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
		now := time.Now().Unix()

		userWindow := slidingwindow.New(10, 10)
		for i := range 5 {
			userWindow.TryRecord(now - int64(i))
		}
		originalValue.Counts[entityKey{Kind: entityKindUser, Value: "user1"}] = userWindow

		ipWindow := slidingwindow.New(10, 10)
		for i := range 3 {
			ipWindow.TryRecord(now - int64(i))
		}
		originalValue.Counts[entityKey{Kind: entityKindIP, Value: "192.168.1.1"}] = ipWindow

		// Update with same config
		rl.UpdateConfig(endpoints)

		updatedValue := rl.rateLimitingMap[key]
		assert.Equal(t, originalValue, updatedValue, "should be same instance")
		assert.Equal(t, 5, updatedValue.Counts[entityKey{Kind: entityKindUser, Value: "user1"}].Count(now))
		assert.Equal(t, 3, updatedValue.Counts[entityKey{Kind: entityKindIP, Value: "192.168.1.1"}].Count(now))
	})

	t.Run("resets data when config changed", func(t *testing.T) {
		rl := New()

		initialEndpoints := []EndpointConfig{
			makeEndpointConfig("GET", "/api/test", true, 10, 300000),
		}
		rl.UpdateConfig(initialEndpoints)

		key := endpointKey{Method: "GET", Route: "/api/test"}

		// Add some data
		now := time.Now().Unix()
		userWindow := slidingwindow.New(10, 10)
		for i := range 5 {
			userWindow.TryRecord(now - int64(i))
		}

		rl.rateLimitingMap[key].Counts[entityKey{Kind: entityKindUser, Value: "user1"}] = userWindow

		// Update with different config
		changedEndpoints := []EndpointConfig{
			makeEndpointConfig("GET", "/api/test", true, 20, 300000),
		}
		rl.UpdateConfig(changedEndpoints)

		value := rl.rateLimitingMap[key]
		require.NotNil(t, value)
		assert.Equal(t, 20, value.Config.MaxRequests)
		assert.Empty(t, value.Counts)
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
		rl.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")
		rl.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")
		rl.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")

		status := rl.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")
		assert.True(t, status.Block, "should block after exceeding limit on wildcard route")

		// /api/users/123 should also match /api/*
		rl2 := New()
		rl2.UpdateConfig(endpoints)
		rl2.ShouldRateLimitRequest("POST", "/api/users/123", "user2", "192.168.1.2")
		rl2.ShouldRateLimitRequest("POST", "/api/users/123", "user2", "192.168.1.2")
		rl2.ShouldRateLimitRequest("POST", "/api/users/123", "user2", "192.168.1.2")

		status2 := rl2.ShouldRateLimitRequest("POST", "/api/users/123", "user2", "192.168.1.2")
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
		rl.ShouldRateLimitRequest("POST", "/api/test", "user1", "192.168.1.1")
		rl.ShouldRateLimitRequest("POST", "/api/test", "user1", "192.168.1.1")

		status := rl.ShouldRateLimitRequest("POST", "/api/test", "user1", "192.168.1.1")
		assert.True(t, status.Block, "should block POST requests matching wildcard")

		// GET requests should not match
		rl2 := New()
		rl2.UpdateConfig(endpoints)
		rl2.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")
		rl2.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")
		rl2.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")

		status2 := rl2.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")
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
			rl.ShouldRateLimitRequest("GET", "/api/posts/123", "user1", "192.168.1.1")
			rl.ShouldRateLimitRequest("GET", "/api/posts/123", "user1", "192.168.1.1")

			status := rl.ShouldRateLimitRequest("GET", "/api/posts/123", "user1", "192.168.1.1")
			assert.True(t, status.Block, "should block based on most restrictive wildcard limit (2 requests)")

			// /api/users/123 only matches /api/*, so should use that limit (10 requests)
			rl2 := New()
			rl2.UpdateConfig(endpoints)
			rl2.ShouldRateLimitRequest("GET", "/api/users/123", "user1", "192.168.1.1")
			rl2.ShouldRateLimitRequest("GET", "/api/users/123", "user1", "192.168.1.1")
			rl2.ShouldRateLimitRequest("GET", "/api/users/123", "user1", "192.168.1.1")

			status2 := rl2.ShouldRateLimitRequest("GET", "/api/users/123", "user1", "192.168.1.1")
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
			rl.ShouldRateLimitRequest("GET", "/api/posts/123", "user1", "192.168.1.1")
			rl.ShouldRateLimitRequest("GET", "/api/posts/123", "user1", "192.168.1.1")

			status := rl.ShouldRateLimitRequest("GET", "/api/posts/123", "user1", "192.168.1.1")
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
		rl.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")
		rl.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")

		status := rl.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")
		assert.True(t, status.Block, "should block based on exact route limit (2 requests), not wildcard")

		// /api/other should match the wildcard
		rl2 := New()
		rl2.UpdateConfig(endpoints)
		rl2.ShouldRateLimitRequest("GET", "/api/other", "user1", "192.168.1.1")
		rl2.ShouldRateLimitRequest("GET", "/api/other", "user1", "192.168.1.1")
		rl2.ShouldRateLimitRequest("GET", "/api/other", "user1", "192.168.1.1")

		status2 := rl2.ShouldRateLimitRequest("GET", "/api/other", "user1", "192.168.1.1")
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
		rl.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")
		rl.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")

		status := rl.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1")
		assert.True(t, status.Block, "should block based on exact method limit (2 requests), not wildcard method")

		// POST /api/test should match the wildcard method (*)
		rl2 := New()
		rl2.UpdateConfig(endpoints)
		rl2.ShouldRateLimitRequest("POST", "/api/test", "user1", "192.168.1.1")
		rl2.ShouldRateLimitRequest("POST", "/api/test", "user1", "192.168.1.1")
		rl2.ShouldRateLimitRequest("POST", "/api/test", "user1", "192.168.1.1")

		status2 := rl2.ShouldRateLimitRequest("POST", "/api/test", "user1", "192.168.1.1")
		assert.False(t, status2.Block, "should not block based on wildcard method limit (10 requests)")
	})
}
