package helpers

import (
	. "github.com/AikidoSec/zen-internals-agent/aikido_types"
	"github.com/stretchr/testify/assert"
	"testing"
)

// sampleRouteMetadata creates a new RouteMetadata for testing.
func sampleRouteMetadata(url, method, route string) RouteMetadata {
	if route == "" {
		route = "/posts/:number"
	}
	if method == "" {
		method = "POST"
	}
	if url == "" {
		url = "http://localhost:4000/posts/3"
	}
	return RouteMetadata{
		Route:  route,
		URL:    url,
		Method: method,
	}
}

func TestMatchEndpoints(t *testing.T) {
	t.Run("testInvalidUrlAndNoRoute", func(t *testing.T) {
		result := MatchEndpoints(sampleRouteMetadata("", "", "abc"), nil)
		assert.Nil(t, result)
	})

	t.Run("testNoUrlAndNoRoute", func(t *testing.T) {
		result := MatchEndpoints(sampleRouteMetadata("", "", "GET"), nil)
		assert.Nil(t, result)
	})

	t.Run("testNoMethod", func(t *testing.T) {
		result := MatchEndpoints(sampleRouteMetadata("/posts/:id", "http://localhost:4000/posts/3", ""), nil)
		assert.Nil(t, result)
	})

	t.Run("testItReturnsUndefinedIfNothingFound", func(t *testing.T) {
		result := MatchEndpoints(sampleRouteMetadata("", "", ""), nil)
		assert.Nil(t, result)
	})

	t.Run("testItReturnsEndpointBasedOnRoute", func(t *testing.T) {
		endpoints := []Endpoint{
			{
				Method: "POST",
				Route:  "/posts/:number",
				RateLimiting: RateLimiting{
					Enabled:        true,
					MaxRequests:    10,
					WindowSizeInMS: 1000,
				},
				AllowedIPAddresses: []string{},
				ForceProtectionOff: false,
			},
		}
		result := MatchEndpoints(sampleRouteMetadata("", "", ""), endpoints)
		assert.Equal(t, endpoints, result)
	})

	t.Run("testItReturnsEndpointBasedOnRelativeUrl", func(t *testing.T) {
		endpoints := []Endpoint{
			{
				Method: "POST",
				Route:  "/posts/:number",
				RateLimiting: RateLimiting{
					Enabled:        true,
					MaxRequests:    10,
					WindowSizeInMS: 1000,
				},
				AllowedIPAddresses: []string{},
				ForceProtectionOff: false,
			},
		}
		result := MatchEndpoints(sampleRouteMetadata("/posts/3", "POST", "/posts/:number"), endpoints)
		assert.Equal(t, endpoints, result)
	})
}
