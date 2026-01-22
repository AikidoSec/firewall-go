//go:build !integration

package echo_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	zenecho "github.com/AikidoSec/firewall-go/instrumentation/sources/labstack/echo.v4"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_Disabled(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	zen.SetDisabled(true)

	require.True(t, zen.IsDisabled())

	e := echo.New()
	e.Use(zenecho.GetMiddleware())

	handlerCalled := false
	e.GET("/test", func(c echo.Context) error {
		handlerCalled = true

		reqCtx := request.GetContext(c.Request().Context())
		require.Nil(t, reqCtx, "Request context should not be created when zen is disabled")

		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	e.ServeHTTP(w, req)

	require.True(t, handlerCalled)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "ok", w.Body.String())
}

func TestMiddleware_NotLoaded(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	originalLoaded := config.IsZenLoaded()
	defer func() {
		zen.SetDisabled(originalDisabled)
		config.SetZenLoaded(originalLoaded)
	}()

	zen.SetDisabled(false)
	config.SetZenLoaded(false)

	require.False(t, zen.IsDisabled())
	require.False(t, zen.ShouldProtect())

	e := echo.New()
	e.Use(zenecho.GetMiddleware())

	handlerCalled := false
	e.GET("/test", func(c echo.Context) error {
		handlerCalled = true

		reqCtx := request.GetContext(c.Request().Context())
		require.Nil(t, reqCtx, "Request context should not be created when zen is not loaded")

		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	e.ServeHTTP(w, req)

	require.True(t, handlerCalled)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "ok", w.Body.String())
}
