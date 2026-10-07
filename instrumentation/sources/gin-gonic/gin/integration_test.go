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
	// gin.Default() calls New() internally, which itself calls With() once;
	// Default() then calls With() again directly. Both guard against the
	// zen middleware being registered twice.
	require.NoError(t, zen.Protect())

	router := gin.Default()
	router.ContextWithFallback = true

	require.Len(t, router.Handlers, 3, "gin.Default() should register zen, Logger, and Recovery - no more")

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

func TestGinWithChainedAfterNew(t *testing.T) {
	// New() already registers zen via its own internal With() call;
	// chaining another With() must not register it a second time, and
	// must still apply the caller's own option.
	require.NoError(t, zen.Protect())

	router := gin.New().With(func(e *gin.Engine) {
		e.RemoveExtraSlash = true
	})
	router.ContextWithFallback = true

	assert.True(t, router.RemoveExtraSlash, "option passed to With should still be applied")
	require.Len(t, router.Handlers, 1, "zen middleware should be registered exactly once")

	router.GET("/route", func(c *gin.Context) {
		ctx := request.GetContext(c)
		require.NotNil(t, ctx, "request context should be set")
	})

	r := httptest.NewRequest("GET", "/route", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)
}

func TestGinWithChainedAfterDefault(t *testing.T) {
	// Default() alone already calls With() twice; chaining a third With()
	// call must still not register zen again.
	require.NoError(t, zen.Protect())

	var optionApplied bool
	router := gin.Default().With(func(e *gin.Engine) {
		optionApplied = true
	})
	router.ContextWithFallback = true

	assert.True(t, optionApplied, "option passed to With should still be applied")
	require.Len(t, router.Handlers, 3, "zen, Logger, and Recovery should be registered exactly once")

	router.GET("/route", func(c *gin.Context) {
		ctx := request.GetContext(c)
		require.NotNil(t, ctx, "request context should be set")
	})

	r := httptest.NewRequest("GET", "/route", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)
}

func TestGinWithMultipleChainedCalls(t *testing.T) {
	// Every With() call in a long chain must still apply its own option,
	// while zen is only ever registered once - on the very first call.
	require.NoError(t, zen.Protect())

	var calls []string
	router := gin.New().
		With(func(e *gin.Engine) { calls = append(calls, "a") }).
		With(func(e *gin.Engine) { calls = append(calls, "b") }).
		With(func(e *gin.Engine) { calls = append(calls, "c") })

	assert.Equal(t, []string{"a", "b", "c"}, calls, "every chained option should still run")
	require.Len(t, router.Handlers, 1, "zen middleware should be registered exactly once despite multiple With calls")
}
