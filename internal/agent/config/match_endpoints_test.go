package config

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/stretchr/testify/assert"
)

// sampleRouteMetadata creates a new RouteMetadata for testing.
func sampleRouteMetadata(url, method, route string) RouteMetadata {
	return RouteMetadata{
		Route:  route,
		URL:    url,
		Method: method,
	}
}

func TestMatchEndpoints(t *testing.T) {
	t.Run("testInvalidUrlAndNoRoute", func(t *testing.T) {
		result := MatchEndpoints(sampleRouteMetadata("abc", "", ""))
		assert.Nil(t, result)
	})

	t.Run("testNoUrlAndNoRoute", func(t *testing.T) {
		result := MatchEndpoints(sampleRouteMetadata("", "POST", ""))
		assert.Nil(t, result)
	})

	t.Run("testNoMethod", func(t *testing.T) {
		result := MatchEndpoints(sampleRouteMetadata("http://localhost:4000/posts/3", "", "/posts/:id"))
		assert.Nil(t, result)
	})

	t.Run("testItReturnsUndefinedIfNothingFound", func(t *testing.T) {
		result := MatchEndpoints(sampleRouteMetadata("", "", ""))
		assert.Nil(t, result)
	})

	t.Run("testItReturnsEndpointBasedOnRoute", func(t *testing.T) {
		serviceConfig.Endpoints = []aikido_types.Endpoint{
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

		result := MatchEndpoints(sampleRouteMetadata("http://localhost:4000/posts/3", "POST", "/posts/:number"))
		assert.Equal(t, serviceConfig.Endpoints, result)
	})

	t.Run("testItReturnsEndpointBasedOnRelativeUrl", func(t *testing.T) {
		serviceConfig.Endpoints = []aikido_types.Endpoint{
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
		result := MatchEndpoints(sampleRouteMetadata("/posts/3", "POST", "/posts/:number"))
		assert.Equal(t, serviceConfig.Endpoints, result)
	})

	t.Run("testItReturnsEndpointBasedOnWildcard", func(t *testing.T) {
		serviceConfig.Endpoints = []aikido_types.Endpoint{
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
		result := MatchEndpoints(sampleRouteMetadata("http://localhost:4000/posts/3", "POST", "/posts/:number"))
		assert.Equal(t, serviceConfig.Endpoints, result)
	})

	t.Run("testItReturnsEndpointBasedOnWildcardWithRelativeUrl", func(t *testing.T) {
		serviceConfig.Endpoints = []aikido_types.Endpoint{
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
		result := MatchEndpoints(sampleRouteMetadata("/posts/3", "POST", "/posts/:number"))
		assert.Equal(t, serviceConfig.Endpoints, result)
	})

	t.Run("testItFavorsMoreSpecificWildcard", func(t *testing.T) {
		serviceConfig.Endpoints = []aikido_types.Endpoint{
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
			serviceConfig.Endpoints[1],
			serviceConfig.Endpoints[0],
		}
		result := MatchEndpoints(sampleRouteMetadata("http://localhost:4000/posts/3/comments/10", "POST", "/posts/:number/comments/:number"))
		assert.Equal(t, expected, result)
	})

	t.Run("testItMatchesWildcardRouteWithSpecificMethod", func(t *testing.T) {
		serviceConfig.Endpoints = []aikido_types.Endpoint{
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
		result := MatchEndpoints(sampleRouteMetadata("http://localhost:4000/posts/3/comments/10", "POST", "/posts/:number/comments/:number"))
		assert.Equal(t, serviceConfig.Endpoints, result)
	})

	t.Run("testItPrefersSpecificRouteOverWildcard", func(t *testing.T) {
		serviceConfig.Endpoints = []aikido_types.Endpoint{
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
			serviceConfig.Endpoints[1],
			serviceConfig.Endpoints[0],
		}

		result := MatchEndpoints(sampleRouteMetadata("http://localhost:4000/api/coach", "POST", "/api/coach"))
		assert.Equal(t, expected, result)
	})

	t.Run("testItPrefersSpecificMethodOverWildcardFirstCase", func(t *testing.T) {
		routeMetadata := sampleRouteMetadata(
			"http://localhost:4000/api/test", "POST", "/api/test",
		)

		serviceConfig.Endpoints = []aikido_types.Endpoint{
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
			serviceConfig.Endpoints[1],
			serviceConfig.Endpoints[0],
		}
		result := MatchEndpoints(routeMetadata)
		assert.Equal(t, expected, result)
	})

	t.Run("testItPrefersSpecificMethodOverWildcardSecondCase", func(t *testing.T) {
		routeMetadata := sampleRouteMetadata(
			"http://localhost:4000/api/test", "POST", "/api/test",
		)

		serviceConfig.Endpoints = []aikido_types.Endpoint{
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
			serviceConfig.Endpoints[0],
			serviceConfig.Endpoints[1],
		}
		result := MatchEndpoints(routeMetadata)
		assert.Equal(t, expected, result)
	})
}
