//go:build integration

package gin_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/AikidoSec/firewall-go/instrumentation"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGinIsAutomaticallyInstrumented(t *testing.T) {
	require.NoError(t, zen.Protect())

	router := gin.New()
	router.ContextWithFallback = true

	router.GET("/route", func(c *gin.Context) {
		ctx := request.GetContext(c)
		require.NotNil(t, ctx, "request context should be set")

		assert.Equal(t, "gin", ctx.Source)
		assert.Equal(t, "/route", ctx.Route)
		assert.Equal(t, map[string][]string{
			"query": {"value"},
		}, ctx.Query)
	})

	r := httptest.NewRequest("GET", "/route?query=value", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)
}

func TestGinIsInstrumentedWhenConstructorPassedByValue(t *testing.T) {
	require.NoError(t, zen.Protect())

	f := gin.Default
	router := f()
	router.ContextWithFallback = true

	router.GET("/route", func(c *gin.Context) {
		ctx := request.GetContext(c)
		require.NotNil(t, ctx, "request context should be set")

		assert.Equal(t, "gin", ctx.Source)
		assert.Equal(t, "/route", ctx.Route)
	})

	r := httptest.NewRequest("GET", "/route", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)
}

func TestGinDefaultIsInstrumentedExactlyOnce(t *testing.T) {
	// gin.Default() calls New() internally, so this guards against the
	// zen hook running twice for the same request.
	require.NoError(t, zen.Protect())

	router := gin.Default()
	router.ContextWithFallback = true

	router.GET("/route", func(c *gin.Context) {})

	r := httptest.NewRequest("GET", "/route", http.NoBody)
	w := httptest.NewRecorder()

	agent.Stats().GetAndClear()

	router.ServeHTTP(w, r)

	require.Eventually(t, func() bool {
		stats := agent.Stats().GetAndClear()
		return stats.Requests.Total == 1
	}, 100*time.Millisecond, 10*time.Millisecond)
}
