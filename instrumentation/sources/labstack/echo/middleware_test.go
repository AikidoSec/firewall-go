//go:build !integration

package echo_test

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http/httptest"
	"strings"
	"testing"

	zenecho "github.com/AikidoSec/firewall-go/instrumentation/sources/labstack/echo"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddlewareAddsContext(t *testing.T) {
	router := echo.New()
	router.Use(zenecho.GetMiddleware())

	router.GET("/route", func(e echo.Context) error {
		ctx := request.GetContext(e.Request().Context())
		require.NotNil(t, ctx, "request context should be set")

		assert.Equal(t, "echo", ctx.Source)
		assert.Equal(t, "/route", ctx.Route)
		assert.Equal(t, map[string][]string{
			"query": {"value"},
		}, ctx.Query)
		return nil
	})

	r := httptest.NewRequest("GET", "/route?query=value", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)
}

func TestMiddlewareGLSFallback(t *testing.T) {
	router := echo.New()
	router.Use(zenecho.GetMiddleware())

	router.GET("/route", func(e echo.Context) error {
		// Test that we can get context using context.Background() (should fallback to GLS)
		ctx := request.GetContext(context.Background())
		require.NotNil(t, ctx, "request context should be set via GLS fallback")

		assert.Equal(t, "echo", ctx.Source)
		assert.Equal(t, "/route", ctx.Route)
		return nil
	})

	r := httptest.NewRequest("GET", "/route", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)
}

func BenchmarkMiddleware(b *testing.B) {
	router := echo.New()
	router.Use(zenecho.GetMiddleware())

	router.GET("/route", func(e echo.Context) error { return nil })

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r := httptest.NewRequest("GET", "/route", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
		}
	})
}

func TestMiddlewarePreservesBodyForJSON(t *testing.T) {
	router := echo.New()
	router.Use(zenecho.GetMiddleware())

	var bodyReadInHandler string
	router.POST("/route", func(e echo.Context) error {
		var data map[string]any
		err := e.Bind(&data)
		require.NoError(t, err, "Should be able to bind JSON after middleware")

		bodyReadInHandler = data["username"].(string)
		return e.JSON(200, data)
	})

	jsonBody := `{"username":"bob","email":"bob@example.com"}`
	r := httptest.NewRequest("POST", "/route", strings.NewReader(jsonBody))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)

	assert.Equal(t, "bob", bodyReadInHandler)
	assert.Equal(t, 200, w.Code)
}

func TestMiddlewarePreservesBodyForURLEncoded(t *testing.T) {
	router := echo.New()
	router.Use(zenecho.GetMiddleware())

	var bodyReadInHandler string
	router.POST("/route", func(e echo.Context) error {
		username := e.FormValue("username")
		bodyReadInHandler = username
		return e.String(200, "ok")
	})

	formData := "username=bob&password=secret"
	r := httptest.NewRequest("POST", "/route", strings.NewReader(formData))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)

	assert.Equal(t, "bob", bodyReadInHandler)
	assert.Equal(t, 200, w.Code)
}

func TestMiddlewarePreservesBodyForMultipart(t *testing.T) {
	router := echo.New()
	router.Use(zenecho.GetMiddleware())

	var fieldReadInHandler string
	router.POST("/route", func(e echo.Context) error {
		field1 := e.FormValue("field1")
		fieldReadInHandler = field1
		return e.String(200, "ok")
	})

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	err := writer.WriteField("field1", "value1")
	require.NoError(t, err)
	err = writer.Close()
	require.NoError(t, err)

	r := httptest.NewRequest("POST", "/route", body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)

	assert.Equal(t, "value1", fieldReadInHandler)
	assert.Equal(t, 200, w.Code)
}

func TestMiddlewarePreservesBodyForRawReadAfterFormParsing(t *testing.T) {
	router := echo.New()
	router.Use(zenecho.GetMiddleware())

	var bodyReadInHandler string
	router.POST("/route", func(e echo.Context) error {
		bodyBytes, err := io.ReadAll(e.Request().Body)
		require.NoError(t, err, "Should be able to read raw body after form parsing in middleware")
		bodyReadInHandler = string(bodyBytes)
		return e.String(200, "ok")
	})

	originalBody := "username=bob&password=secret"
	r := httptest.NewRequest("POST", "/route", strings.NewReader(originalBody))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)

	assert.Equal(t, originalBody, bodyReadInHandler)
	assert.Equal(t, 200, w.Code)
}
