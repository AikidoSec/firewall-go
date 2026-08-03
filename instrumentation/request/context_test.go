package request

import (
	"context"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetContext(t *testing.T) {
	ip := "10.0.0.1"
	routeParams := map[string]string{"id": "42"}
	body := map[string]string{"name": "test"}

	ctx := SetContext(context.Background(), ContextData{
		Source:        "gin",
		Route:         "/api/users/:id",
		RouteParams:   routeParams,
		RemoteAddress: &ip,
		Body:          body,
		URL:           "http://example.com/api/users?q=1",
		Path:          "/api/users",
		Method:        "POST",
		Query:         map[string][]string{"q": {"1"}},
		Headers:       map[string][]string{"content-type": {"application/json"}},
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
		ctx := SetContext(context.Background(), ContextData{
			Source: "test",
			Route:  "/path",
			Path:   "/path",
			Method: "GET",
			URL:    "http://example.com/path",
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
		ctx := SetContext(context.Background(), ContextData{
			Source: "wrap-test",
			Route:  "/wrapped",
			Path:   "/wrapped",
			Method: "GET",
			URL:    "http://example.com/wrapped",
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
		ctx := SetContext(context.Background(), ContextData{
			Source: "test",
			Route:  "/done",
			Path:   "/done",
			Method: "GET",
			URL:    "http://example.com/done",
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
