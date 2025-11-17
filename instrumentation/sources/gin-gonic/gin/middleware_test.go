//go:build !integration

package gin_test

import (
	"context"
	"net/http/httptest"
	"testing"

	zengin "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddlewareAddsContext(t *testing.T) {
	router := gin.New()
	router.ContextWithFallback = true
	router.Use(zengin.GetMiddleware())

	router.GET("/route", func(c *gin.Context) {
		ctx := request.GetContext(c)
		require.NotNil(t, ctx, "request context should be set")

		assert.Equal(t, "gin", ctx.Source)
		assert.Equal(t, "/route", ctx.Route)
		assert.Equal(t, map[string][]string{
			"query": {"value"},
		}, ctx.Query)
	})

	r := httptest.NewRequest("GET", "/route?query=value", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)
}

func TestMiddlewareHandlesNilContext(t *testing.T) {
	middleware := zengin.GetMiddleware()

	require.NotPanics(t, func() {
		middleware(nil)
	})
}

func TestMiddlewareGLSFallback(t *testing.T) {
	router := gin.New()
	router.ContextWithFallback = true
	router.Use(zengin.GetMiddleware())

	router.GET("/route", func(c *gin.Context) {
		// Test that we can get context using context.Background() (should fallback to GLS)
		ctx := request.GetContext(context.Background())
		require.NotNil(t, ctx, "request context should be set via GLS fallback")

		assert.Equal(t, "gin", ctx.Source)
		assert.Equal(t, "/route", ctx.Route)
	})

	r := httptest.NewRequest("GET", "/route", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)
}

func BenchmarkMiddleware(b *testing.B) {
	router := gin.New()
	router.ContextWithFallback = true
	router.Use(zengin.GetMiddleware())

	router.GET("/route", func(c *gin.Context) {})

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r := httptest.NewRequest("GET", "/route", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
		}
	})
}
