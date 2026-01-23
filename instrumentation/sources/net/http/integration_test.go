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

func TestServeMuxIsAutomaticallyInstrumented(t *testing.T) {
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
