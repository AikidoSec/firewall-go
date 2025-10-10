package zen

import (
	"context"
	"net/http"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetUser(t *testing.T) {
	t.Run("ValidInput", func(t *testing.T) {
		// Setup
		ctx := context.Background()
		req, _ := http.NewRequest("GET", "http://example.com/test", nil)
		remoteAddr := "127.0.0.1"
		ctx = request.SetContext(ctx, req, "/test", "test", &remoteAddr, nil)

		// Execute
		resultCtx := SetUser(ctx, "user123", "John Doe")

		// Verify
		require.NotNil(t, resultCtx, "Expected context to be returned")

		reqCtx := request.GetContext(resultCtx)
		require.NotNil(t, reqCtx, "Expected request context to exist")

		userID := reqCtx.GetUserID()
		assert.Equal(t, "user123", userID, "Expected user ID to be 'user123'")
	})

	t.Run("EmptyID", func(t *testing.T) {
		// Setup
		ctx := context.Background()
		req, _ := http.NewRequest("GET", "http://example.com/test", nil)
		remoteAddr := "127.0.0.1"
		ctx = request.SetContext(ctx, req, "/test", "test", &remoteAddr, nil)

		// Execute
		resultCtx := SetUser(ctx, "", "John Doe")

		// Verify
		require.NotNil(t, resultCtx, "Expected context to be returned")

		reqCtx := request.GetContext(resultCtx)
		require.NotNil(t, reqCtx, "Expected request context to exist")

		userID := reqCtx.GetUserID()
		assert.Empty(t, userID, "Expected user ID to be empty")
	})

	t.Run("EmptyName", func(t *testing.T) {
		// Setup
		ctx := context.Background()
		req, _ := http.NewRequest("GET", "http://example.com/test", nil)
		remoteAddr := "127.0.0.1"
		ctx = request.SetContext(ctx, req, "/test", "test", &remoteAddr, nil)

		// Execute
		resultCtx := SetUser(ctx, "user123", "")

		// Verify
		require.NotNil(t, resultCtx, "Expected context to be returned")

		reqCtx := request.GetContext(resultCtx)
		require.NotNil(t, reqCtx, "Expected request context to exist")

		userID := reqCtx.GetUserID()
		assert.Empty(t, userID, "Expected user ID to be empty")
	})

	t.Run("NilRequestContext", func(t *testing.T) {
		// Setup - context without request context
		ctx := context.Background()

		// Execute
		resultCtx := SetUser(ctx, "user123", "John Doe")

		// Verify
		require.NotNil(t, resultCtx, "Expected context to be returned")

		// Verify that the context is still the same
		assert.Equal(t, ctx, resultCtx, "Expected context to remain unchanged when request context is nil")
	})

	t.Run("MiddlewareAlreadyExecuted", func(t *testing.T) {
		// Setup
		ctx := context.Background()
		req, _ := http.NewRequest("GET", "http://example.com/test", nil)
		remoteAddr := "127.0.0.1"
		ctx = request.SetContext(ctx, req, "/test", "test", &remoteAddr, nil)

		// Mark middleware as executed
		reqCtx := request.GetContext(ctx)
		require.NotNil(t, reqCtx, "Expected request context to exist")
		reqCtx.MarkMiddlewareExecuted()

		// Execute
		resultCtx := SetUser(ctx, "user123", "John Doe")

		// Verify
		require.NotNil(t, resultCtx, "Expected context to be returned")

		// User should not be set
		userID := reqCtx.GetUserID()
		assert.Empty(t, userID, "Expected user ID to be empty when middleware already executed")
	})
}
