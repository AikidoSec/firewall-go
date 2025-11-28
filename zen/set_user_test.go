package zen_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetUser(t *testing.T) {
	t.Run("ValidInput", func(t *testing.T) {
		// Setup
		req, _ := http.NewRequest("GET", "http://example.com/test", nil)
		remoteAddr := "127.0.0.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/test",
			RemoteAddress: &remoteAddr,
		})

		// Execute
		resultCtx, err := zen.SetUser(ctx, "user123", "John Doe")

		// Verify
		require.NotNil(t, resultCtx, "Expected context to be returned")
		require.NoError(t, err)

		reqCtx := request.GetContext(resultCtx)
		require.NotNil(t, reqCtx, "Expected request context to exist")

		user := reqCtx.GetUser()
		assert.Equal(t, "user123", user.ID, "Expected user ID to be 'user123'")
		assert.Equal(t, "John Doe", user.Name, "Expected name to be 'John Doe'")
	})

	t.Run("EmptyID", func(t *testing.T) {
		// Setup
		req, _ := http.NewRequest("GET", "http://example.com/test", nil)
		remoteAddr := "127.0.0.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/test",
			RemoteAddress: &remoteAddr,
		})

		// Execute
		resultCtx, err := zen.SetUser(ctx, "", "John Doe")

		// Verify
		require.NotNil(t, resultCtx, "Expected context to be returned")
		require.ErrorIs(t, err, zen.ErrUserIDOrNameEmpty)

		reqCtx := request.GetContext(resultCtx)
		require.NotNil(t, reqCtx, "Expected request context to exist")

		userID := reqCtx.GetUser().ID
		assert.Empty(t, userID, "Expected user ID to be empty")
	})

	t.Run("EmptyName", func(t *testing.T) {
		// Setup
		req, _ := http.NewRequest("GET", "http://example.com/test", nil)
		remoteAddr := "127.0.0.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/test",
			RemoteAddress: &remoteAddr,
		})

		// Execute
		resultCtx, err := zen.SetUser(ctx, "user123", "")

		// Verify
		require.NotNil(t, resultCtx, "Expected context to be returned")
		require.ErrorIs(t, err, zen.ErrUserIDOrNameEmpty)

		reqCtx := request.GetContext(resultCtx)
		require.NotNil(t, reqCtx, "Expected request context to exist")

		userID := reqCtx.GetUser().ID
		assert.Empty(t, userID, "Expected user ID to be empty")
	})

	t.Run("NilRequestContext", func(t *testing.T) {
		// Setup - context without request context
		ctx := context.Background()

		// Execute
		resultCtx, err := zen.SetUser(ctx, "user123", "John Doe")

		// Verify
		require.NotNil(t, resultCtx, "Expected context to be returned")
		require.NoError(t, err)

		// Verify that the context is still the same
		assert.Equal(t, ctx, resultCtx, "Expected context to remain unchanged when request context is nil")
	})

	t.Run("MiddlewareAlreadyExecuted", func(t *testing.T) {
		// Setup
		req, _ := http.NewRequest("GET", "http://example.com/test", nil)
		remoteAddr := "127.0.0.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/test",
			RemoteAddress: &remoteAddr,
		})

		// Mark middleware as executed
		reqCtx := request.GetContext(ctx)
		require.NotNil(t, reqCtx, "Expected request context to exist")
		reqCtx.MarkMiddlewareExecuted()

		// Execute
		resultCtx, err := zen.SetUser(ctx, "user123", "John Doe")

		// Verify
		require.NotNil(t, resultCtx, "Expected context to be returned")
		require.NoError(t, err)

		// User should not be set
		userID := reqCtx.GetUser().ID
		assert.Empty(t, userID, "Expected user ID to be empty when middleware already executed")
	})

	t.Run("UserAvailableImmediatelyForAttackDetection", func(t *testing.T) {
		ip := "127.0.0.1"
		req := httptest.NewRequest("POST", "/api/users", nil)
		req.Header.Set("Content-Type", "application/json")
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/test",
			RemoteAddress: &ip,
		})

		userID := "user-123"
		userName := "John Doe"

		// This would normally be called in the service middleware
		ctx, err := zen.SetUser(ctx, userID, userName)

		// Verify the user is set on the context
		reqCtx := request.GetContext(ctx)
		require.NotNil(t, reqCtx, "Request context should exist")
		require.NoError(t, err)
		assert.Equal(t, userID, reqCtx.GetUser().ID, "User ID should be set on context")
	})
}

// ExampleSetUser demonstrates how to use SetUser to associate a user with a request context.
func ExampleSetUser() {
	err := zen.Protect()
	if err != nil {
		log.Fatal(err)
	}

	// Create a test request
	req, _ := http.NewRequest("GET", "/test", nil)
	ctx := context.Background()

	// Set user in context
	ctx, err = zen.SetUser(ctx, "user123", "John Doe")
	if err != nil {
		log.Println(err)
		return
	}

	// Use the updated context with your request
	_ = req.WithContext(ctx)

	// The user is now associated with this request context
	fmt.Println("User set in context")
	// Output: User set in context
}
