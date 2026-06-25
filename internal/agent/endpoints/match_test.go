package endpoints

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/ipaddr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sampleRouteMetadata creates a new RouteMetadata for testing.
func sampleRouteMetadata(method, route string) RouteMetadata {
	return RouteMetadata{
		Route:  route,
		Method: method,
	}
}

func TestFindMatches(t *testing.T) {
	t.Run("testInvalidUrlAndNoRoute", func(t *testing.T) {
		result := FindMatches([]config.Endpoint{}, sampleRouteMetadata("", ""))
		assert.Nil(t, result)
	})

	t.Run("testNoUrlAndNoRoute", func(t *testing.T) {
		result := FindMatches([]config.Endpoint{}, sampleRouteMetadata("POST", ""))
		assert.Nil(t, result)
	})

	t.Run("testNoMethod", func(t *testing.T) {
		endpoints := []config.Endpoint{
			{
				Method: "POST",
				Route:  "/posts/:number",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    10,
					WindowSizeInMS: 1000,
				},
				AllowedIPAddresses: ipaddr.MatchList{},
				ForceProtectionOff: false,
			},
		}
		result := FindMatches(endpoints, sampleRouteMetadata("", "/posts/:id"))
		assert.Nil(t, result)
	})

	t.Run("testItReturnsUndefinedIfNothingFound", func(t *testing.T) {
		result := FindMatches([]config.Endpoint{}, sampleRouteMetadata("", ""))
		assert.Nil(t, result)
	})

	t.Run("testItReturnsEndpointBasedOnRoute", func(t *testing.T) {
		endpoints := []config.Endpoint{
			{
				Method: "POST",
				Route:  "/posts/:number",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    10,
					WindowSizeInMS: 1000,
				},
				AllowedIPAddresses: ipaddr.MatchList{},
				ForceProtectionOff: false,
			},
		}

		result := FindMatches(endpoints, sampleRouteMetadata("POST", "/posts/:number"))
		assert.Equal(t, endpoints, result)
	})

	t.Run("testItReturnsEndpointBasedOnRelativeUrl", func(t *testing.T) {
		endpoints := []config.Endpoint{
			{
				Method: "POST",
				Route:  "/posts/:number",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    10,
					WindowSizeInMS: 1000,
				},
				AllowedIPAddresses: ipaddr.MatchList{},
				ForceProtectionOff: false,
			},
		}
		result := FindMatches(endpoints, sampleRouteMetadata("POST", "/posts/:number"))
		assert.Equal(t, endpoints, result)
	})

	t.Run("testItReturnsEndpointBasedOnWildcard", func(t *testing.T) {
		endpoints := []config.Endpoint{
			{
				Method: "*",
				Route:  "/posts/*",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    10,
					WindowSizeInMS: 1000,
				},
				AllowedIPAddresses: ipaddr.MatchList{},
				ForceProtectionOff: false,
			},
		}
		result := FindMatches(endpoints, sampleRouteMetadata("POST", "/posts/:number"))
		assert.Equal(t, endpoints, result)
	})

	t.Run("testItReturnsEndpointBasedOnWildcardWithRelativeUrl", func(t *testing.T) {
		endpoints := []config.Endpoint{
			{
				Method: "*",
				Route:  "/posts/*",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    10,
					WindowSizeInMS: 1000,
				},
				AllowedIPAddresses: ipaddr.MatchList{},
				ForceProtectionOff: false,
			},
		}
		result := FindMatches(endpoints, sampleRouteMetadata("POST", "/posts/:number"))
		assert.Equal(t, endpoints, result)
	})

	t.Run("testItFavorsMoreSpecificWildcard", func(t *testing.T) {
		endpoints := []config.Endpoint{
			{
				Method: "*",
				Route:  "/posts/*",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    10,
					WindowSizeInMS: 1000,
				},
				AllowedIPAddresses: ipaddr.MatchList{},
				ForceProtectionOff: false,
			},
			{
				Method: "*",
				Route:  "/posts/*/comments/*",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    10,
					WindowSizeInMS: 1000,
				},
				AllowedIPAddresses: ipaddr.MatchList{},
				ForceProtectionOff: false,
			},
		}

		expected := []config.Endpoint{
			endpoints[1],
			endpoints[0],
		}
		result := FindMatches(endpoints, sampleRouteMetadata("POST", "/posts/:number/comments/:number"))
		assert.Equal(t, expected, result)
	})

	t.Run("testItMatchesWildcardRouteWithSpecificMethod", func(t *testing.T) {
		endpoints := []config.Endpoint{
			{
				Method: "POST",
				Route:  "/posts/*/comments/*",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    10,
					WindowSizeInMS: 1000,
				},
				AllowedIPAddresses: ipaddr.MatchList{},
				ForceProtectionOff: false,
			},
		}
		result := FindMatches(endpoints, sampleRouteMetadata("POST", "/posts/:number/comments/:number"))
		assert.Equal(t, endpoints, result)
	})

	t.Run("testItPrefersSpecificRouteOverWildcard", func(t *testing.T) {
		endpoints := []config.Endpoint{
			{
				Method: "*",
				Route:  "/api/*",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    20,
					WindowSizeInMS: 60000,
				},
				AllowedIPAddresses: ipaddr.MatchList{},
				ForceProtectionOff: false,
			},
			{
				Method: "POST",
				Route:  "/api/coach",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    100,
					WindowSizeInMS: 60000,
				},
				AllowedIPAddresses: ipaddr.MatchList{},
				ForceProtectionOff: false,
			},
		}

		expected := []config.Endpoint{
			endpoints[1],
			endpoints[0],
		}

		result := FindMatches(endpoints, sampleRouteMetadata("POST", "/api/coach"))
		assert.Equal(t, expected, result)
	})

	t.Run("testItPrefersSpecificMethodOverWildcardFirstCase", func(t *testing.T) {
		routeMetadata := sampleRouteMetadata("POST", "/api/test")

		endpoints := []config.Endpoint{
			{
				Method: "*",
				Route:  "/api/test",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    20,
					WindowSizeInMS: 60000,
				},
				AllowedIPAddresses: ipaddr.MatchList{},
				ForceProtectionOff: false,
			},
			{
				Method: "POST",
				Route:  "/api/test",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    100,
					WindowSizeInMS: 60000,
				},
				AllowedIPAddresses: ipaddr.MatchList{},
				ForceProtectionOff: false,
			},
		}

		expected := []config.Endpoint{
			endpoints[1],
			endpoints[0],
		}
		result := FindMatches(endpoints, routeMetadata)
		assert.Equal(t, expected, result)
	})

	t.Run("testItPrefersSpecificMethodOverWildcardSecondCase", func(t *testing.T) {
		routeMetadata := sampleRouteMetadata("POST", "/api/test")

		endpoints := []config.Endpoint{
			{
				Method: "POST",
				Route:  "/api/test",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    100,
					WindowSizeInMS: 60000,
				},
				AllowedIPAddresses: ipaddr.MatchList{},
				ForceProtectionOff: false,
			},
			{
				Method: "*",
				Route:  "/api/test",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    20,
					WindowSizeInMS: 60000,
				},
				AllowedIPAddresses: ipaddr.MatchList{},
				ForceProtectionOff: false,
			},
		}

		expected := []config.Endpoint{
			endpoints[0],
			endpoints[1],
		}
		result := FindMatches(endpoints, routeMetadata)
		assert.Equal(t, expected, result)
	})
}

func TestIsForceProtectionOff(t *testing.T) {
	block := true
	config.UpdateServiceConfig(&aikido_types.CloudConfigData{
		Block: &block,
		Endpoints: []aikido_types.Endpoint{
			{Method: "POST", Route: "/api/danger", ForceProtectionOff: true},
			{Method: "*", Route: "/api/wildcard", ForceProtectionOff: true},
			{Method: "GET", Route: "/api/safe", ForceProtectionOff: false},
		},
	}, nil)

	require.True(t, IsForceProtectionOff("POST", "/api/danger"), "exact match with force protection off")
	require.True(t, IsForceProtectionOff("GET", "/api/wildcard"), "wildcard method with force protection off")
	require.False(t, IsForceProtectionOff("GET", "/api/safe"), "force protection off is false")
	require.False(t, IsForceProtectionOff("GET", "/api/danger"), "wrong method should not match")
	require.False(t, IsForceProtectionOff("POST", "/api/unknown"), "unmatched route returns false")
	require.False(t, IsForceProtectionOff("", "/api/danger"), "empty method returns false")
}
