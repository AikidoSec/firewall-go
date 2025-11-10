package zen_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShouldBlockRequest(t *testing.T) {
	// Basic test to ensure function doesn't panic
	ctx := context.Background()
	result := zen.ShouldBlockRequest(ctx)

	require.Nil(t, result, "Expected nil result for empty context")
}

func TestShouldBlockRequest_BlockedUser(t *testing.T) {
	req := httptest.NewRequest("GET", "/route", nil)
	ip := "127.0.0.1"
	reqCtx := request.SetContext(context.Background(), req, "/route", "/test", &ip, nil)

	zen.SetUser(reqCtx, "banned", "Banned User")

	config.SetUserBlocked("banned")

	response := zen.ShouldBlockRequest(reqCtx)
	require.NotNil(t, response)
	assert.Equal(t, "blocked", response.Type)
	assert.Equal(t, "user", response.Trigger)
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
			ctx = request.SetContext(ctx, r, "/test", "GET", &remoteAddr, nil)

			// Set user in context
			ctx = zen.SetUser(ctx, "user123", "John Doe")
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
