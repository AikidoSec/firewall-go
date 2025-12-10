package endpoints

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/stretchr/testify/assert"
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
		result := FindMatches([]aikido_types.Endpoint{}, sampleRouteMetadata("", ""))
		assert.Nil(t, result)
	})

	t.Run("testNoUrlAndNoRoute", func(t *testing.T) {
		result := FindMatches([]aikido_types.Endpoint{}, sampleRouteMetadata("POST", ""))
		assert.Nil(t, result)
	})

	t.Run("testNoMethod", func(t *testing.T) {
		endpoints := []aikido_types.Endpoint{
			{
				Method: "POST",
				Route:  "/posts/:number",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    10,
					WindowSizeInMS: 1000,
				},
				AllowedIPAddresses: []string{},
				ForceProtectionOff: false,
			},
		}
		result := FindMatches(endpoints, sampleRouteMetadata("", "/posts/:id"))
		assert.Nil(t, result)
	})

	t.Run("testItReturnsUndefinedIfNothingFound", func(t *testing.T) {
		result := FindMatches([]aikido_types.Endpoint{}, sampleRouteMetadata("", ""))
		assert.Nil(t, result)
	})

	t.Run("testItReturnsEndpointBasedOnRoute", func(t *testing.T) {
		endpoints := []aikido_types.Endpoint{
			{
				Method: "POST",
				Route:  "/posts/:number",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    10,
					WindowSizeInMS: 1000,
				},
				AllowedIPAddresses: []string{},
				ForceProtectionOff: false,
			},
		}

		result := FindMatches(endpoints, sampleRouteMetadata("POST", "/posts/:number"))
		assert.Equal(t, endpoints, result)
	})

	t.Run("testItReturnsEndpointBasedOnRelativeUrl", func(t *testing.T) {
		endpoints := []aikido_types.Endpoint{
			{
				Method: "POST",
				Route:  "/posts/:number",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    10,
					WindowSizeInMS: 1000,
				},
				AllowedIPAddresses: []string{},
				ForceProtectionOff: false,
			},
		}
		result := FindMatches(endpoints, sampleRouteMetadata("POST", "/posts/:number"))
		assert.Equal(t, endpoints, result)
	})

	t.Run("testItReturnsEndpointBasedOnWildcard", func(t *testing.T) {
		endpoints := []aikido_types.Endpoint{
			{
				Method: "*",
				Route:  "/posts/*",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    10,
					WindowSizeInMS: 1000,
				},
				AllowedIPAddresses: []string{},
				ForceProtectionOff: false,
			},
		}
		result := FindMatches(endpoints, sampleRouteMetadata("POST", "/posts/:number"))
		assert.Equal(t, endpoints, result)
	})

	t.Run("testItReturnsEndpointBasedOnWildcardWithRelativeUrl", func(t *testing.T) {
		endpoints := []aikido_types.Endpoint{
			{
				Method: "*",
				Route:  "/posts/*",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    10,
					WindowSizeInMS: 1000,
				},
				AllowedIPAddresses: []string{},
				ForceProtectionOff: false,
			},
		}
		result := FindMatches(endpoints, sampleRouteMetadata("POST", "/posts/:number"))
		assert.Equal(t, endpoints, result)
	})

	t.Run("testItFavorsMoreSpecificWildcard", func(t *testing.T) {
		endpoints := []aikido_types.Endpoint{
			{
				Method: "*",
				Route:  "/posts/*",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    10,
					WindowSizeInMS: 1000,
				},
				AllowedIPAddresses: []string{},
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
				AllowedIPAddresses: []string{},
				ForceProtectionOff: false,
			},
		}

		expected := []aikido_types.Endpoint{
			endpoints[1],
			endpoints[0],
		}
		result := FindMatches(endpoints, sampleRouteMetadata("POST", "/posts/:number/comments/:number"))
		assert.Equal(t, expected, result)
	})

	t.Run("testItMatchesWildcardRouteWithSpecificMethod", func(t *testing.T) {
		endpoints := []aikido_types.Endpoint{
			{
				Method: "POST",
				Route:  "/posts/*/comments/*",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    10,
					WindowSizeInMS: 1000,
				},
				AllowedIPAddresses: []string{},
				ForceProtectionOff: false,
			},
		}
		result := FindMatches(endpoints, sampleRouteMetadata("POST", "/posts/:number/comments/:number"))
		assert.Equal(t, endpoints, result)
	})

	t.Run("testItPrefersSpecificRouteOverWildcard", func(t *testing.T) {
		endpoints := []aikido_types.Endpoint{
			{
				Method: "*",
				Route:  "/api/*",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    20,
					WindowSizeInMS: 60000,
				},
				AllowedIPAddresses: []string{},
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
				AllowedIPAddresses: []string{},
				ForceProtectionOff: false,
			},
		}

		expected := []aikido_types.Endpoint{
			endpoints[1],
			endpoints[0],
		}

		result := FindMatches(endpoints, sampleRouteMetadata("POST", "/api/coach"))
		assert.Equal(t, expected, result)
	})

	t.Run("testItPrefersSpecificMethodOverWildcardFirstCase", func(t *testing.T) {
		routeMetadata := sampleRouteMetadata("POST", "/api/test")

		endpoints := []aikido_types.Endpoint{
			{
				Method: "*",
				Route:  "/api/test",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    20,
					WindowSizeInMS: 60000,
				},
				AllowedIPAddresses: []string{},
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
				AllowedIPAddresses: []string{},
				ForceProtectionOff: false,
			},
		}

		expected := []aikido_types.Endpoint{
			endpoints[1],
			endpoints[0],
		}
		result := FindMatches(endpoints, routeMetadata)
		assert.Equal(t, expected, result)
	})

	t.Run("testItPrefersSpecificMethodOverWildcardSecondCase", func(t *testing.T) {
		routeMetadata := sampleRouteMetadata("POST", "/api/test")

		endpoints := []aikido_types.Endpoint{
			{
				Method: "POST",
				Route:  "/api/test",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    100,
					WindowSizeInMS: 60000,
				},
				AllowedIPAddresses: []string{},
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
				AllowedIPAddresses: []string{},
				ForceProtectionOff: false,
			},
		}

		expected := []aikido_types.Endpoint{
			endpoints[0],
			endpoints[1],
		}
		result := FindMatches(endpoints, routeMetadata)
		assert.Equal(t, expected, result)
	})
}
