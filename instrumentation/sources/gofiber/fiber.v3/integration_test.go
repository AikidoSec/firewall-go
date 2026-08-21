//go:build integration

package fiber_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/AikidoSec/firewall-go/instrumentation"
	"github.com/AikidoSec/firewall-go/instrumentation/sources/gofiber/fiber.v3/routeresolver"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRouteResolverIsRegistered(t *testing.T) {
	require.NotNil(t, routeresolver.Get(), "zen-go should inject the fiber route resolver")
}

func TestFiberNewIsAutomaticallyInstrumented(t *testing.T) {
	require.NoError(t, zen.Protect())

	app := fiber.New()

	app.Get("/route", func(c fiber.Ctx) error {
		ctx := request.GetContext(c.Context())
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

// customCtx is a minimal fiber.CustomCtx implementation, following the shape
// fiber's own docs and tests use for fiber.NewWithCustomCtx.
type customCtx struct {
	fiber.DefaultCtx
}

// fiber.NewWithCustomCtx is a second app constructor (used when the app needs
// extra methods on Ctx) and should be instrumented the same as fiber.New.
func TestFiberNewWithCustomCtxIsAutomaticallyInstrumented(t *testing.T) {
	require.NoError(t, zen.Protect())

	app := fiber.NewWithCustomCtx(func(app *fiber.App) fiber.CustomCtx {
		return &customCtx{DefaultCtx: *fiber.NewDefaultCtx(app)}
	})

	app.Get("/route", func(c fiber.Ctx) error {
		ctx := request.GetContext(c.Context())
		require.NotNil(t, ctx, "request context should be set")

		assert.Equal(t, "fiber", ctx.Source)
		assert.Equal(t, "/route", ctx.Route)

		return nil
	})

	r := httptest.NewRequest("GET", "/route?query=value", http.NoBody)
	resp, err := app.Test(r)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestFiberNewWithCustomCtxIsInstrumentedExactlyOnce(t *testing.T) {
	// fiber.NewWithCustomCtx calls New(...) internally, so this guards against
	// the zen middleware being registered twice.
	require.NoError(t, zen.Protect())

	app := fiber.NewWithCustomCtx(func(app *fiber.App) fiber.CustomCtx {
		return &customCtx{DefaultCtx: *fiber.NewDefaultCtx(app)}
	})

	assert.Equal(t, uint32(1), app.HandlersCount(), "fiber.NewWithCustomCtx() should register only the zen middleware - no more")
}

// A NewWithCustomCtx app mounted under a New() app gets middleware from both
// wrap rules; only the first should report, same as two New() apps.
func TestMountedCustomCtxAppReportsRequestOnce(t *testing.T) {
	require.NoError(t, zen.Protect())

	agent.Stats().GetAndClear()

	sub := fiber.NewWithCustomCtx(func(app *fiber.App) fiber.CustomCtx {
		return &customCtx{DefaultCtx: *fiber.NewDefaultCtx(app)}
	})
	sub.Get("/thing", func(c fiber.Ctx) error {
		ctx := request.GetContext(c.Context())
		require.NotNil(t, ctx, "request context should be set")

		assert.Equal(t, "/api/thing", ctx.Route)
		return c.SendString("ok")
	})

	app := fiber.New()
	app.Use("/api", sub)

	r := httptest.NewRequest("GET", "/api/thing", http.NoBody)
	resp, err := app.Test(r)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 1, agent.Stats().GetAndClear().Requests.Total)
}

// The injected resolver reads fiber's unexported router internals, so this
// compares what it produced against fiber's own answer once the handler runs.
// A fiber upgrade that renames those internals fails here instead of silently
// degrading route reporting and per-endpoint protections.
func TestResolvedRouteMatchesFiber(t *testing.T) {
	require.NoError(t, zen.Protect())

	assertMatchesFiber := func(c fiber.Ctx) error {
		ctx := request.GetContext(c.Context())
		require.NotNil(t, ctx, "request context should be set")

		assert.Equal(t, c.Route().Path, ctx.Route, "resolved route should match fiber")

		want := c.Route().Params
		if len(want) == 0 {
			assert.Empty(t, ctx.RouteParams)
		} else {
			gotParams := make(map[string]string, len(want))
			for _, name := range want {
				gotParams[name] = c.Params(name)
			}
			assert.Equal(t, gotParams, ctx.RouteParams, "resolved params should match fiber")
		}

		return nil
	}

	app := fiber.New()

	// Literal registered before param, and the reverse, to pin precedence.
	app.Get("/users/new", assertMatchesFiber)
	app.Get("/users/:id", assertMatchesFiber)
	app.Get("/things/:id", assertMatchesFiber)
	app.Get("/things/special", assertMatchesFiber)

	app.Get("/static/*", assertMatchesFiber)
	app.Get("/opt/:p?", assertMatchesFiber)
	app.Get("/articles/:date-:slug", assertMatchesFiber)
	app.Get("/typed/:id<int>", assertMatchesFiber)
	app.Get("/Mixed/:name", assertMatchesFiber)

	group := app.Group("/api/:version").Group("/users/:userid")
	group.Get("/posts/:postid", assertMatchesFiber)

	paths := []string{
		"/users/new",
		"/users/123",
		"/things/special",
		"/things/123",
		"/static/css/app.css",
		"/opt",
		"/opt/xyz",
		"/articles/20170116-hello-world",
		"/typed/42",
		"/mixed/AbC-XyZ",
		"/api/v1/users/user123/posts/post456",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest("GET", path, http.NoBody)
			resp, err := app.Test(r)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}

// A custom Ctx implementation (not *fiber.DefaultCtx) must still resolve the
// route pattern instead of silently falling back to the raw request path.
func TestResolvedRouteForCustomCtx(t *testing.T) {
	require.NoError(t, zen.Protect())

	app := fiber.NewWithCustomCtx(func(app *fiber.App) fiber.CustomCtx {
		return &customCtx{DefaultCtx: *fiber.NewDefaultCtx(app)}
	})

	app.Get("/users/:id", func(c fiber.Ctx) error {
		ctx := request.GetContext(c.Context())
		require.NotNil(t, ctx, "request context should be set")

		assert.Equal(t, "/users/:id", ctx.Route, "resolved route should match fiber's pattern, not the raw path")
		assert.Equal(t, map[string]string{"id": "123"}, ctx.RouteParams)

		return nil
	})

	r := httptest.NewRequest("GET", "/users/123", http.NoBody)
	resp, err := app.Test(r)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// Both fiber.New calls are instrumented, so a mounted app must still report once.
func TestMountedAppReportsRequestOnce(t *testing.T) {
	require.NoError(t, zen.Protect())

	agent.Stats().GetAndClear()

	sub := fiber.New()
	sub.Get("/thing", func(c fiber.Ctx) error {
		ctx := request.GetContext(c.Context())
		require.NotNil(t, ctx, "request context should be set")

		assert.Equal(t, "/api/thing", ctx.Route)
		return c.SendString("ok")
	})

	app := fiber.New()
	app.Use("/api", sub)

	r := httptest.NewRequest("GET", "/api/thing", http.NoBody)
	resp, err := app.Test(r)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 1, agent.Stats().GetAndClear().Requests.Total)
}

func TestMiddlewareNestedRouters(t *testing.T) {
	require.NoError(t, zen.Protect())

	t.Run("group with multiple params", func(t *testing.T) {
		app := fiber.New()

		routeGroup := app.Group("/route/:id")
		routeGroup.Get("/subrouter/:anotherid", func(c fiber.Ctx) error {
			ctx := request.GetContext(c.Context())
			require.NotNil(t, ctx, "request context should be set")

			assert.Equal(t, "fiber", ctx.Source)
			assert.Equal(t, "/route/:id/subrouter/:anotherid", ctx.Route)
			assert.Equal(t, "123", ctx.RouteParams["id"])
			assert.Equal(t, "456", ctx.RouteParams["anotherid"])

			return nil
		})

		r := httptest.NewRequest("GET", "/route/123/subrouter/456", http.NoBody)
		resp, err := app.Test(r)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("deeply nested groups", func(t *testing.T) {
		app := fiber.New()

		apiGroup := app.Group("/api/:version")
		usersGroup := apiGroup.Group("/users/:userid")
		usersGroup.Get("/posts/:postid", func(c fiber.Ctx) error {
			ctx := request.GetContext(c.Context())
			require.NotNil(t, ctx, "request context should be set")

			assert.Equal(t, "fiber", ctx.Source)
			assert.Equal(t, "/api/:version/users/:userid/posts/:postid", ctx.Route)
			assert.Equal(t, "v1", ctx.RouteParams["version"])
			assert.Equal(t, "user123", ctx.RouteParams["userid"])
			assert.Equal(t, "post456", ctx.RouteParams["postid"])

			return nil
		})

		r := httptest.NewRequest("GET", "/api/v1/users/user123/posts/post456", http.NoBody)
		resp, err := app.Test(r)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

// Endpoint config is matched by route pattern, so a parameterised route can only
// be protected once the pattern is resolved before dispatch.
func TestParameterisedEndpointIsProtected(t *testing.T) {
	require.NoError(t, zen.Protect())

	block := true
	config.UpdateServiceConfig(&aikido_types.CloudConfigData{
		Block: &block,
		Endpoints: []aikido_types.Endpoint{
			{
				Method:             "GET",
				Route:              "/admin/:section",
				AllowedIPAddresses: []string{"192.168.0.1"},
			},
		},
	}, &aikido_types.ListsConfigData{})
	t.Cleanup(func() {
		noBlock := false
		config.UpdateServiceConfig(&aikido_types.CloudConfigData{
			Block: &noBlock,
		}, &aikido_types.ListsConfigData{})
	})

	app := fiber.New(fiber.Config{
		ProxyHeader: fiber.HeaderXForwardedFor,
		TrustProxy:  true,
		TrustProxyConfig: fiber.TrustProxyConfig{
			Proxies: []string{"0.0.0.0"},
		},
	})
	app.Get("/admin/:section", func(c fiber.Ctx) error { return nil })

	t.Run("unapproved ip is blocked", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/admin/users", http.NoBody)
		r.Header.Set("X-Forwarded-For", "192.168.1.1")

		resp, err := app.Test(r)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("approved ip is allowed", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/admin/users", http.NoBody)
		r.Header.Set("X-Forwarded-For", "192.168.0.1")

		resp, err := app.Test(r)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
