//go:build !integration

package fiber_test

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	zenfiber "github.com/AikidoSec/firewall-go/instrumentation/sources/gofiber/fiber.v2"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/internal/testutil"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	testutil.RegisterGLSFallback()

	original := config.IsZenLoaded()
	config.SetZenLoaded(true)

	code := m.Run()

	config.SetZenLoaded(original)
	os.Exit(code)
}

// newTestApp configures ProxyHeader so tests can control c.IP() via the
// X-Forwarded-For header: app.Test() serves requests over an in-memory
// connection whose RemoteAddr is always fixed, so RemoteAddr on the request
// has no effect on the IP fiber observes.
func newTestApp() *fiber.App {
	return fiber.New(fiber.Config{ProxyHeader: fiber.HeaderXForwardedFor})
}

// Route patterns and params need the resolver that zen-go injects into fiber,
// which is absent here; see integration_test.go for the instrumented behaviour.
// Uninstrumented, the route falls back to the request path and params are unset.
func TestMiddlewareAddsContext(t *testing.T) {
	app := newTestApp()
	app.Use(zenfiber.GetMiddleware())

	app.Get("/route/:id", func(c *fiber.Ctx) error {
		ctx := request.GetContext(c.UserContext())
		require.NotNil(t, ctx, "request context should be set")

		assert.Equal(t, "fiber", ctx.Source)
		assert.Equal(t, map[string][]string{
			"query": {"value"},
		}, ctx.Query)
		assert.Equal(t, "/route/foo", ctx.Route)
		assert.Empty(t, ctx.RouteParams)

		return nil
	})

	r := httptest.NewRequest("GET", "/route/foo?query=value", http.NoBody)
	resp, err := app.Test(r)
	require.NoError(t, err)
	defer resp.Body.Close()
}

func TestMiddlewareSetsIPInContext(t *testing.T) {
	app := newTestApp()
	app.Use(zenfiber.GetMiddleware())

	app.Get("/route", func(c *fiber.Ctx) error {
		ctx := request.GetContext(c.UserContext())
		require.NotNil(t, ctx, "request context should be set")

		assert.Equal(t, "192.168.1.1", ctx.GetIP())
		return nil
	})

	r := httptest.NewRequest("GET", "/route", http.NoBody)
	r.Header.Set("X-Forwarded-For", "192.168.1.1")
	resp, err := app.Test(r)
	require.NoError(t, err)
	defer resp.Body.Close()
}

func TestMiddlewareGLSFallback(t *testing.T) {
	app := newTestApp()
	app.Use(zenfiber.GetMiddleware())

	app.Get("/route", func(c *fiber.Ctx) error {
		// Test that we can get context using context.Background() (should fallback to GLS)
		ctx := request.GetContext(context.Background())
		require.NotNil(t, ctx, "request context should be set via GLS fallback")

		assert.Equal(t, "fiber", ctx.Source)
		assert.Equal(t, "/route", ctx.Route)
		return nil
	})

	r := httptest.NewRequest("GET", "/route", http.NoBody)
	resp, err := app.Test(r)
	require.NoError(t, err)
	defer resp.Body.Close()
}

func TestMiddlewareBlockingRequests(t *testing.T) {
	t.Cleanup(func() {
		noBlock := false
		config.UpdateServiceConfig(&aikido_types.CloudConfigData{
			Block: &noBlock,
		}, &aikido_types.ListsConfigData{})
	})

	block := true
	config.UpdateServiceConfig(&aikido_types.CloudConfigData{
		Block: &block,
		Endpoints: []aikido_types.Endpoint{
			{
				Method:             "GET",
				Route:              "/admin",
				AllowedIPAddresses: []string{"192.168.0.1"},
			},
		},
	}, &aikido_types.ListsConfigData{
		AllowedIPAddresses: []aikido_types.IPList{
			{
				Source:      "test-allowed",
				Description: "Test allowed IPs",
				IPs:         []string{"8.8.8.0/24"},
			},
		},
		BlockedIPAddresses: []aikido_types.IPList{
			{
				Source:      "test",
				Description: "localhost",
				IPs:         []string{"127.0.0.1"},
			},
		},
		BlockedUserAgents: "bot.*",
	})

	app := newTestApp()
	app.Use(zenfiber.GetMiddleware())

	app.Get("/route", func(c *fiber.Ctx) error {
		t.Fatal("request should have been blocked")
		return nil
	})

	app.Get("/allowed-route", func(c *fiber.Ctx) error { return nil })

	app.Get("/admin", func(c *fiber.Ctx) error { return nil })

	t.Run("blocked ip", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/route", http.NoBody)
		r.Header.Set("X-Forwarded-For", "127.0.0.1")

		resp, err := app.Test(r)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("blocked user agent", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/route", http.NoBody)
		r.Header.Set("User-Agent", "bot-test")

		resp, err := app.Test(r)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("block route with unapproved ip", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/admin", http.NoBody)
		r.Header.Set("X-Forwarded-For", "192.168.1.1")

		resp, err := app.Test(r)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("allow route with approved ip", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/admin", http.NoBody)
		r.Header.Set("X-Forwarded-For", "192.168.0.1")

		resp, err := app.Test(r)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("blocked by global allow list", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/route", http.NoBody)
		r.Header.Set("X-Forwarded-For", "203.0.114.1")

		resp, err := app.Test(r)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("allowed by global allow list", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/allowed-route", http.NoBody)
		r.Header.Set("X-Forwarded-For", "8.8.8.100")

		resp, err := app.Test(r)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestMiddlewarePreservesBodyForJSON(t *testing.T) {
	app := newTestApp()
	app.Use(zenfiber.GetMiddleware())

	var bodyReadInHandler string
	app.Post("/route", func(c *fiber.Ctx) error {
		var data map[string]any
		err := json.Unmarshal(c.Body(), &data)
		require.NoError(t, err, "Should be able to decode JSON after middleware")

		bodyReadInHandler = data["username"].(string)
		return c.JSON(data)
	})

	jsonBody := `{"username":"bob","email":"bob@example.com"}`
	r := httptest.NewRequest("POST", "/route", strings.NewReader(jsonBody))
	r.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(r)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, "bob", bodyReadInHandler)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestMiddlewarePreservesBodyForURLEncoded(t *testing.T) {
	app := newTestApp()
	app.Use(zenfiber.GetMiddleware())

	var bodyReadInHandler string
	app.Post("/route", func(c *fiber.Ctx) error {
		bodyReadInHandler = c.FormValue("username")
		return c.SendString("ok")
	})

	formData := "username=bob&password=secret"
	r := httptest.NewRequest("POST", "/route", strings.NewReader(formData))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := app.Test(r)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, "bob", bodyReadInHandler)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestMiddlewarePreservesBodyForMultipart(t *testing.T) {
	app := newTestApp()
	app.Use(zenfiber.GetMiddleware())

	var fieldReadInHandler string
	app.Post("/route", func(c *fiber.Ctx) error {
		fieldReadInHandler = c.FormValue("field1")
		return c.SendString("ok")
	})

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	err := writer.WriteField("field1", "value1")
	require.NoError(t, err)
	err = writer.Close()
	require.NoError(t, err)

	r := httptest.NewRequest("POST", "/route", body)
	r.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := app.Test(r)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, "value1", fieldReadInHandler)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestMiddlewarePreservesBodyForRawReadAfterFormParsing(t *testing.T) {
	app := newTestApp()
	app.Use(zenfiber.GetMiddleware())

	var bodyReadInHandler string
	app.Post("/route", func(c *fiber.Ctx) error {
		bodyReadInHandler = string(c.Body())
		return c.SendString("ok")
	})

	originalBody := "username=bob&password=secret"
	r := httptest.NewRequest("POST", "/route", strings.NewReader(originalBody))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := app.Test(r)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, originalBody, bodyReadInHandler)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestMiddlewareCallsOnPostRequest(t *testing.T) {
	agent.Stats().GetAndClear()

	app := newTestApp()
	app.Use(zenfiber.GetMiddleware())

	app.Get("/route", func(c *fiber.Ctx) error {
		return c.SendStatus(http.StatusOK)
	})

	r := httptest.NewRequest("GET", "/route?query=value", http.NoBody)
	resp, err := app.Test(r)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		stats := agent.Stats().GetAndClear()
		require.Equal(c, 1, stats.Requests.Total)
	}, 100*time.Millisecond, 10*time.Millisecond)
}

// Mounting merges the sub-app's routes into the parent, so both apps' middleware runs.
func TestMiddlewareRunsOnceForMountedApp(t *testing.T) {
	agent.Stats().GetAndClear()

	sub := newTestApp()
	sub.Use(zenfiber.GetMiddleware())

	contexts := 0
	sub.Get("/thing", func(c *fiber.Ctx) error {
		ctx := request.GetContext(c.UserContext())
		require.NotNil(t, ctx, "request context should be set")
		contexts++

		return c.SendString("ok")
	})

	app := newTestApp()
	app.Use(zenfiber.GetMiddleware())
	app.Mount("/api", sub)

	r := httptest.NewRequest("GET", "/api/thing", http.NoBody)
	resp, err := app.Test(r)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 1, contexts)
	assert.Equal(t, 1, agent.Stats().GetAndClear().Requests.Total)
}
