package zen_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/ratelimiting"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupRateLimitingConfig(t *testing.T, method, route string, maxRequests int) {
	t.Helper()
	block := true
	cloudConfig := &aikido_types.CloudConfigData{
		Success:   true,
		ServiceID: 1,
		Endpoints: []aikido_types.Endpoint{
			{
				Method: method,
				Route:  route,
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    maxRequests,
					WindowSizeInMS: 100000,
				},
				AllowedIPAddresses: []string{},
				ForceProtectionOff: false,
			},
		},
		BlockedUserIds:   []string{},
		BypassedIPs:      []string{},
		ReceivedAnyStats: false,
		Block:            &block,
	}
	config.UpdateServiceConfig(cloudConfig, nil)

	ratelimiting.UpdateConfig([]ratelimiting.EndpointConfig{
		{
			Method: method,
			Route:  route,
			RateLimiting: struct {
				Enabled        bool
				MaxRequests    int
				WindowSizeInMS int
			}{
				Enabled:        true,
				MaxRequests:    maxRequests,
				WindowSizeInMS: 100000,
			},
		},
	})
}

func createRequestContext(t *testing.T, method, route, ip string, userID, userName string) context.Context {
	t.Helper()
	return createRequestContextWithGroup(t, method, route, ip, userID, userName, "")
}

func createRequestContextWithGroup(t *testing.T, method, route, ip string, userID, userName, groupID string) context.Context {
	t.Helper()
	req := httptest.NewRequest(method, route, nil)
	reqCtx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         route,
		RemoteAddress: &ip,
	})
	if userID != "" {
		_, err := zen.SetUser(reqCtx, userID, userName)
		require.NoError(t, err)
	}
	if groupID != "" {
		_, err := zen.SetRateLimitGroup(reqCtx, groupID)
		require.NoError(t, err)
	}
	return reqCtx
}

func TestShouldBlockRequest(t *testing.T) {
	// Basic test to ensure function doesn't panic
	ctx := context.Background()
	result := zen.ShouldBlockRequest(ctx)

	require.Nil(t, result, "Expected nil result for empty context")
}

func TestShouldBlockRequest_BlockedUser(t *testing.T) {
	req := httptest.NewRequest("GET", "/route", nil)
	ip := "127.0.0.1"
	reqCtx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/route",
		RemoteAddress: &ip,
	})

	_, err := zen.SetUser(reqCtx, "banned", "Banned User")
	require.NoError(t, err)

	config.SetUserBlocked("banned")

	response := zen.ShouldBlockRequest(reqCtx)
	require.NotNil(t, response)
	assert.Equal(t, "blocked", response.Type)
	assert.Equal(t, "user", response.Trigger)
	assert.Nil(t, response.IP)
}

func TestShouldBlockRequest_RateLimitedByUser(t *testing.T) {
	setupRateLimitingConfig(t, "GET", "/api/test", 2)

	// Update counts to exceed limit
	ratelimiting.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1", "")
	ratelimiting.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1", "")
	ratelimiting.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1", "")

	reqCtx := createRequestContext(t, "GET", "/api/test", "192.168.1.1", "user1", "Test User")

	response := zen.ShouldBlockRequest(reqCtx)
	require.NotNil(t, response)
	assert.Equal(t, "rate-limited", response.Type)
	assert.Equal(t, "user", response.Trigger)
	assert.Nil(t, response.IP)
}

func TestShouldBlockRequest_RateLimitedByIP(t *testing.T) {
	// Use wildcard route to match any /api/* endpoint
	setupRateLimitingConfig(t, "POST", "/api/*", 3)

	// Update counts to exceed limit (no user, so rate limit by IP)
	// Use a specific route that matches the wildcard
	ratelimiting.ShouldRateLimitRequest("POST", "/api/submit", "", "10.0.0.1", "")
	ratelimiting.ShouldRateLimitRequest("POST", "/api/submit", "", "10.0.0.1", "")
	ratelimiting.ShouldRateLimitRequest("POST", "/api/submit", "", "10.0.0.1", "")
	ratelimiting.ShouldRateLimitRequest("POST", "/api/submit", "", "10.0.0.1", "")

	reqCtx := createRequestContext(t, "POST", "/api/submit", "10.0.0.1", "", "")

	response := zen.ShouldBlockRequest(reqCtx)
	require.NotNil(t, response)
	assert.Equal(t, "rate-limited", response.Type)
	assert.Equal(t, "ip", response.Trigger)
	assert.NotNil(t, response.IP)
	assert.Equal(t, "10.0.0.1", *response.IP)
}

func TestShouldBlockRequest_NotRateLimited(t *testing.T) {
	setupRateLimitingConfig(t, "GET", "/api/test", 5)

	// Update counts but stay below limit
	ratelimiting.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1", "")
	ratelimiting.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1", "")

	reqCtx := createRequestContext(t, "GET", "/api/test", "192.168.1.1", "user1", "Test User")

	response := zen.ShouldBlockRequest(reqCtx)
	assert.Nil(t, response)
}

func TestShouldBlockRequest_RateLimitedByGroup(t *testing.T) {
	setupRateLimitingConfig(t, "GET", "/api/test", 2)

	// Update counts to exceed limit
	ratelimiting.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1", "group1")
	ratelimiting.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1", "group1")
	ratelimiting.ShouldRateLimitRequest("GET", "/api/test", "user1", "192.168.1.1", "group1")

	reqCtx := createRequestContextWithGroup(t, "GET", "/api/test", "192.168.1.1", "user1", "Test User", "group1")

	response := zen.ShouldBlockRequest(reqCtx)
	require.NotNil(t, response)
	assert.Equal(t, "rate-limited", response.Type)
	assert.Equal(t, "group", response.Trigger)
	assert.Nil(t, response.IP)
}

// ExampleShouldBlockRequest demonstrates the complete middleware pattern with auth and Zen middleware.
func ExampleShouldBlockRequest() {
	err := zen.Protect()
	if err != nil {
		log.Fatal(err)
	}

	// Auth middleware that sets user
	authMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set up proper request context
			ctx := context.Background()
			remoteAddr := "127.0.0.1"
			ctx = request.SetContext(ctx, r, request.ContextData{
				Source:        "test",
				Route:         "/test",
				RemoteAddress: &remoteAddr,
			})

			// Set user in context
			ctx, err = zen.SetUser(ctx, "user123", "John Doe")
			if err != nil {
				log.Println(err)
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	// Zen middleware that checks blocking
	zenMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			blockResult := zen.ShouldBlockRequest(r.Context())
			if blockResult != nil {
				http.Error(w, "Blocked", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	// Handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello")
	})

	// Chain: auth -> zen -> handler
	mux := authMiddleware(zenMiddleware(handler))

	// Test the middleware chain
	req, _ := http.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	// Show the response status and body
	fmt.Printf("Status: %d\n", rr.Code)
	fmt.Printf("Body: %s", rr.Body.String())
	// Output:
	// Status: 200
	// Body: Hello
}
