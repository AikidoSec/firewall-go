package zen_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetRateLimitGroup(t *testing.T) {
	t.Run("ValidInput", func(t *testing.T) {
		// Setup
		req, _ := http.NewRequest("GET", "http://example.com/test", http.NoBody)
		remoteAddr := "127.0.0.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/test",
			RemoteAddress: &remoteAddr,
		})

		// Execute
		resultCtx, err := zen.SetRateLimitGroup(ctx, "group123")

		// Verify
		require.NotNil(t, resultCtx, "Expected context to be returned")
		require.NoError(t, err)

		reqCtx := request.GetContext(resultCtx)
		require.NotNil(t, reqCtx, "Expected request context to exist")

		groupID := reqCtx.GetRateLimitGroup()
		assert.Equal(t, "group123", groupID, "Expected group ID to be 'group123'")
	})

	t.Run("EmptyID", func(t *testing.T) {
		// Setup
		req, _ := http.NewRequest("GET", "http://example.com/test", http.NoBody)
		remoteAddr := "127.0.0.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/test",
			RemoteAddress: &remoteAddr,
		})

		// Execute
		resultCtx, err := zen.SetRateLimitGroup(ctx, "")

		// Verify
		require.NotNil(t, resultCtx, "Expected context to be returned")
		require.ErrorIs(t, err, zen.ErrRateLimitGroupIDEmpty)

		reqCtx := request.GetContext(resultCtx)
		require.NotNil(t, reqCtx, "Expected request context to exist")

		groupID := reqCtx.GetRateLimitGroup()
		assert.Empty(t, groupID, "Expected group ID to be empty")
	})

	t.Run("NilRequestContext", func(t *testing.T) {
		// Setup - context without request context
		ctx := context.Background()

		// Execute
		resultCtx, err := zen.SetRateLimitGroup(ctx, "group123")

		// Verify
		require.NotNil(t, resultCtx, "Expected context to be returned")
		require.NoError(t, err)

		// Verify that the context is still the same
		assert.Equal(t, ctx, resultCtx, "Expected context to remain unchanged when request context is nil")
	})

	t.Run("MiddlewareAlreadyExecuted", func(t *testing.T) {
		// Setup
		req, _ := http.NewRequest("GET", "http://example.com/test", http.NoBody)
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
		resultCtx, err := zen.SetRateLimitGroup(ctx, "group123")

		// Verify
		require.NotNil(t, resultCtx, "Expected context to be returned")
		require.NoError(t, err)

		// Group should not be set
		groupID := reqCtx.GetRateLimitGroup()
		assert.Empty(t, groupID, "Expected group ID to be empty when middleware already executed")
	})
}

// ExampleSetRateLimitGroup demonstrates how to use SetRateLimitGroup to associate a group with a request context.
func ExampleSetRateLimitGroup() {
	err := zen.Protect()
	if err != nil {
		log.Fatal(err)
	}

	// Create a test request
	req, _ := http.NewRequest("GET", "/test", http.NoBody)
	ctx := context.Background()

	// Set rate limit group in context
	ctx, err = zen.SetRateLimitGroup(ctx, "group123")
	if err != nil {
		log.Println(err)
		return
	}

	// Use the updated context with your request
	_ = req.WithContext(ctx)

	// The group is now associated with this request context
	fmt.Println("Rate limit group set in context")
	// Output: Rate limit group set in context
}
