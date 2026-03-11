package request

import (
	"context"
	"net/http"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetContext(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.com/api/users?q=1", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	ip := "10.0.0.1"
	routeParams := map[string]string{"id": "42"}
	body := map[string]string{"name": "test"}

	ctx := SetContext(context.Background(), req, ContextData{
		Source:        "gin",
		Route:         "/api/users/:id",
		RouteParams:   routeParams,
		RemoteAddress: &ip,
		Body:          body,
	})

	reqCtx := request.GetContext(ctx)
	require.NotNil(t, reqCtx)

	assert.Equal(t, "gin", reqCtx.Source)
	assert.Equal(t, "/api/users/:id", reqCtx.Route)
	assert.Equal(t, "POST", reqCtx.Method)
	assert.Equal(t, "/api/users", reqCtx.Path)
	assert.Equal(t, &ip, reqCtx.RemoteAddress)
	assert.Equal(t, routeParams, reqCtx.RouteParams)
}

func TestHasContext(t *testing.T) {
	t.Run("returns false for empty context", func(t *testing.T) {
		assert.False(t, HasContext(context.Background()))
	})

	t.Run("returns true after SetContext", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://example.com/path", http.NoBody)
		require.NoError(t, err)
		ctx := SetContext(context.Background(), req, ContextData{
			Source: "test",
			Route:  "/path",
		})
		assert.True(t, HasContext(ctx))
	})

	t.Run("returns false for nil context", func(t *testing.T) {
		//nolint:staticcheck // We want to test the nil case
		assert.False(t, HasContext(nil))
	})
}

func TestWrap(t *testing.T) {
	t.Run("makes context available via GLS", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://example.com/wrapped", http.NoBody)
		require.NoError(t, err)
		ctx := SetContext(context.Background(), req, ContextData{
			Source: "wrap-test",
			Route:  "/wrapped",
		})

		var glsCtx *request.Context
		Wrap(ctx, func() {
			glsCtx = request.GetContext(context.Background())
		})

		require.NotNil(t, glsCtx)
		assert.Equal(t, "wrap-test", glsCtx.Source)
		assert.Equal(t, "/wrapped", glsCtx.Route)
	})

	t.Run("GLS context not available after Wrap returns", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://example.com/done", http.NoBody)
		require.NoError(t, err)
		ctx := SetContext(context.Background(), req, ContextData{
			Source: "test",
			Route:  "/done",
		})

		Wrap(ctx, func() {})

		glsCtx := request.GetContext(context.Background())
		assert.Nil(t, glsCtx)
	})

	t.Run("calls fn when context is nil", func(t *testing.T) {
		called := false
		//nolint:staticcheck // We want to test the nil case
		Wrap(nil, func() {
			called = true
		})
		assert.True(t, called)
	})
}
