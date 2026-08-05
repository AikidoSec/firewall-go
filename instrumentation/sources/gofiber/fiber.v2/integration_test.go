//go:build integration

package fiber_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/AikidoSec/firewall-go/instrumentation"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFiberNewIsAutomaticallyInstrumented(t *testing.T) {
	require.NoError(t, zen.Protect())

	app := fiber.New()

	app.Get("/route", func(c *fiber.Ctx) error {
		ctx := request.GetContext(c.UserContext())
		require.NotNil(t, ctx, "request context should be set")

		assert.Equal(t, "fiber", ctx.Source)
		assert.Equal(t, "/route", ctx.Route)
		assert.Equal(t, map[string][]string{
			"query": {"value"},
		}, ctx.Query)

		return nil
	})

	r := httptest.NewRequest("GET", "/route?query=value", http.NoBody)
	resp, err := app.Test(r)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
