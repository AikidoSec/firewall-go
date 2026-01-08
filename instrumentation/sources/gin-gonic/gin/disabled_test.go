//go:build !integration

package gin_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	zengin "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_Disabled(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	zen.SetDisabled(true)

	require.True(t, zen.IsDisabled())

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(zengin.GetMiddleware())

	handlerCalled := false
	router.GET("/test", func(c *gin.Context) {
		handlerCalled = true

		reqCtx := request.GetContext(c.Request.Context())
		require.Nil(t, reqCtx, "Request context should not be created when zen is disabled")

		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.True(t, handlerCalled)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "ok", w.Body.String())
}
