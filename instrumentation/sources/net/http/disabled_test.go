//go:build !integration

package http_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	zenhttp "github.com/AikidoSec/firewall-go/instrumentation/sources/net/http"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_Disabled(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	zen.SetDisabled(true)

	require.True(t, zen.IsDisabled())

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		reqCtx := request.GetContext(r.Context())
		require.Nil(t, reqCtx, "Request context should not be created when zen is disabled")

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	wrappedHandler := zenhttp.WrapHandler(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	require.True(t, handlerCalled)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "ok", w.Body.String())
}
