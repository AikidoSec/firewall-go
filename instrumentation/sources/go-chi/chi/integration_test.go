//go:build integration

package chi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/AikidoSec/firewall-go/instrumentation"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChiNewRouterIsAutomaticallyInstrumented(t *testing.T) {
	require.NoError(t, zen.Protect())

	router := chi.NewRouter()

	router.Get("/route", func(w http.ResponseWriter, r *http.Request) {
		ctx := request.GetContext(r.Context())
		require.NotNil(t, ctx, "request context should be set")

		assert.Equal(t, "chi", ctx.Source)
		assert.Equal(t, "/route", ctx.Route)
		assert.Equal(t, map[string][]string{
			"query": {"value"},
		}, ctx.Query)
	})

	r := httptest.NewRequest("GET", "/route?query=value", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)
}

func TestChiNewMuxIsAutomaticallyInstrumented(t *testing.T) {
	require.NoError(t, zen.Protect())

	router := chi.NewMux()

	router.Get("/route", func(w http.ResponseWriter, r *http.Request) {
		ctx := request.GetContext(r.Context())
		require.NotNil(t, ctx, "request context should be set")

		assert.Equal(t, "chi", ctx.Source)
		assert.Equal(t, "/route", ctx.Route)
		assert.Equal(t, map[string][]string{
			"query": {"value"},
		}, ctx.Query)
	})

	r := httptest.NewRequest("GET", "/route?query=value", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)
}
