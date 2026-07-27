//go:build integration

package http_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/AikidoSec/firewall-go/instrumentation"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServeMuxHandleFuncIsAutomaticallyInstrumented(t *testing.T) {
	require.NoError(t, zen.Protect())

	mux := http.NewServeMux()

	mux.HandleFunc("GET /route/{id}", func(w http.ResponseWriter, r *http.Request) {
		ctx := request.GetContext(r.Context())
		require.NotNil(t, ctx, "request context should be set")

		assert.Equal(t, "http.ServeMux", ctx.Source)
		assert.Equal(t, "/route/{id}", ctx.Route)
		assert.Equal(t, map[string][]string{
			"query": {"value"},
		}, ctx.Query)
		assert.Equal(t, map[string]string{
			"id": "abc",
		}, ctx.RouteParams)
	})

	r := httptest.NewRequest("GET", "/route/abc?query=value", http.NoBody)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, r)
}

func TestServeMuxHandleIsAutomaticallyInstrumented(t *testing.T) {
	require.NoError(t, zen.Protect())

	mux := http.NewServeMux()

	mux.Handle("GET /handle-route/{id}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := request.GetContext(r.Context())
		require.NotNil(t, ctx, "request context should be set")

		assert.Equal(t, "http.ServeMux", ctx.Source)
		assert.Equal(t, "/handle-route/{id}", ctx.Route)
		assert.Equal(t, map[string][]string{
			"query": {"value"},
		}, ctx.Query)
		assert.Equal(t, map[string]string{
			"id": "abc",
		}, ctx.RouteParams)
	}))

	r := httptest.NewRequest("GET", "/handle-route/abc?query=value", http.NoBody)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, r)
}

// http.HandleFunc also registers on DefaultServeMux, so it must get the same instrumentation as (*ServeMux).HandleFunc.
func TestPackageLevelHandleFuncIsAutomaticallyInstrumented(t *testing.T) {
	require.NoError(t, zen.Protect())

	var ctx *request.Context
	http.HandleFunc("/package-handlefunc-route/{id}", func(w http.ResponseWriter, r *http.Request) {
		ctx = request.GetContext(r.Context())
	})

	r := httptest.NewRequest("GET", "/package-handlefunc-route/abc?query=value", http.NoBody)
	w := httptest.NewRecorder()

	http.DefaultServeMux.ServeHTTP(w, r)

	require.NotNil(t, ctx, "request context should be set for routes registered with package-level http.HandleFunc")
	assert.Equal(t, "http.ServeMux", ctx.Source)
	assert.Equal(t, "/package-handlefunc-route/{id}", ctx.Route)
	assert.Equal(t, map[string][]string{
		"query": {"value"},
	}, ctx.Query)
	assert.Equal(t, map[string]string{
		"id": "abc",
	}, ctx.RouteParams)
}

// http.Handle also registers on DefaultServeMux, so it must get the same instrumentation as (*ServeMux).Handle.
func TestPackageLevelHandleIsAutomaticallyInstrumented(t *testing.T) {
	require.NoError(t, zen.Protect())

	var ctx *request.Context
	http.Handle("/package-handle-route/{id}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx = request.GetContext(r.Context())
	}))

	r := httptest.NewRequest("GET", "/package-handle-route/abc?query=value", http.NoBody)
	w := httptest.NewRecorder()

	http.DefaultServeMux.ServeHTTP(w, r)

	require.NotNil(t, ctx, "request context should be set for routes registered with package-level http.Handle")
	assert.Equal(t, "http.ServeMux", ctx.Source)
	assert.Equal(t, "/package-handle-route/{id}", ctx.Route)
	assert.Equal(t, map[string][]string{
		"query": {"value"},
	}, ctx.Query)
	assert.Equal(t, map[string]string{
		"id": "abc",
	}, ctx.RouteParams)
}
