//go:build !integration

package fiber_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	zenfiber "github.com/AikidoSec/firewall-go/instrumentation/sources/gofiber/fiber.v2"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_Disabled(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	zen.SetDisabled(true)

	require.True(t, zen.IsDisabled())

	app := fiber.New()
	app.Use(zenfiber.GetMiddleware())

	handlerCalled := false
	app.Get("/test", func(c *fiber.Ctx) error {
		handlerCalled = true

		reqCtx := request.GetContext(c.UserContext())
		require.Nil(t, reqCtx, "Request context should not be created when zen is disabled")

		return c.SendString("ok")
	})

	req := httptest.NewRequest("GET", "/test", http.NoBody)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.True(t, handlerCalled)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "ok", string(body))
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

	app := fiber.New()
	app.Use(zenfiber.GetMiddleware())

	handlerCalled := false
	app.Get("/test", func(c *fiber.Ctx) error {
		handlerCalled = true

		reqCtx := request.GetContext(c.UserContext())
		require.Nil(t, reqCtx, "Request context should not be created when zen is not loaded")

		return c.SendString("ok")
	})

	req := httptest.NewRequest("GET", "/test", http.NoBody)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.True(t, handlerCalled)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "ok", string(body))
}
