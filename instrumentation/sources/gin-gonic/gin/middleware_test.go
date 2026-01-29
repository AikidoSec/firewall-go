//go:build !integration

package gin_test

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	zengin "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	original := config.IsZenLoaded()
	config.SetZenLoaded(true)

	code := m.Run()

	config.SetZenLoaded(original)
	os.Exit(code)
}

func TestMiddlewareAddsContext(t *testing.T) {
	router := gin.New()
	router.ContextWithFallback = true
	router.Use(zengin.GetMiddleware())

	router.GET("/route/:id", func(c *gin.Context) {
		ctx := request.GetContext(c)
		require.NotNil(t, ctx, "request context should be set")

		assert.Equal(t, "gin", ctx.Source)
		assert.Equal(t, "/route/:id", ctx.Route)
		assert.Equal(t, map[string][]string{
			"query": {"value"},
		}, ctx.Query)
		assert.Equal(t, map[string]string{
			"id": "foo",
		}, ctx.RouteParams)
	})

	r := httptest.NewRequest("GET", "/route/foo?query=value", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)
}

func TestMiddlewareGLSFallback(t *testing.T) {
	router := gin.New()
	router.ContextWithFallback = true
	router.Use(zengin.GetMiddleware())

	router.GET("/route", func(c *gin.Context) {
		// Test that we can get context using context.Background() (should fallback to GLS)
		ctx := request.GetContext(context.Background())
		require.NotNil(t, ctx, "request context should be set via GLS fallback")

		assert.Equal(t, "gin", ctx.Source)
		assert.Equal(t, "/route", ctx.Route)
	})

	r := httptest.NewRequest("GET", "/route", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)
}

func TestMiddlewareBlockingRequests(t *testing.T) {
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

	router := gin.New()
	router.ContextWithFallback = true
	router.Use(zengin.GetMiddleware())

	router.GET("/route", func(c *gin.Context) {
		t.Fatal("request should have been blocked")
	})

	router.GET("/allowed-route", func(c *gin.Context) {})

	router.GET("/admin", func(c *gin.Context) {})

	t.Run("blocked ip", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/route", http.NoBody)
		r.RemoteAddr = "127.0.0.1:1234"
		w := httptest.NewRecorder()

		router.ServeHTTP(w, r)

		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("blocked user agent", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/route", http.NoBody)
		r.Header.Set("User-Agent", "bot-test")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, r)

		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("block route with unapproved ip", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/admin", http.NoBody)
		r.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()

		router.ServeHTTP(w, r)

		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("allow route with approved ip", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/admin", http.NoBody)
		r.RemoteAddr = "192.168.0.1:4321"
		w := httptest.NewRecorder()

		router.ServeHTTP(w, r)

		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("blocked by global allow list", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/route", nil)
		r.RemoteAddr = "203.0.114.1:1234"
		w := httptest.NewRecorder()

		router.ServeHTTP(w, r)

		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("allowed by global allow list", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/allowed-route", nil)
		r.RemoteAddr = "8.8.8.100:1234"
		w := httptest.NewRecorder()

		router.ServeHTTP(w, r)

		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func BenchmarkMiddleware(b *testing.B) {
	router := gin.New()
	router.ContextWithFallback = true
	router.Use(zengin.GetMiddleware())

	router.GET("/route", func(c *gin.Context) {})

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r := httptest.NewRequest("GET", "/route", http.NoBody)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
		}
	})
}

func TestMiddlewarePreservesBodyForJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(zengin.GetMiddleware())

	var bodyReadInHandler string
	router.POST("/route", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		require.NoError(t, err, "Should be able to bind JSON after middleware")

		bodyReadInHandler = data["username"].(string)
		c.JSON(200, data)
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
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(zengin.GetMiddleware())

	var bodyReadInHandler string
	router.POST("/route", func(c *gin.Context) {
		username := c.PostForm("username")
		bodyReadInHandler = username
		c.String(200, "ok")
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
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(zengin.GetMiddleware())

	var fieldReadInHandler string
	router.POST("/route", func(c *gin.Context) {
		field1 := c.PostForm("field1")
		fieldReadInHandler = field1
		c.String(200, "ok")
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
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(zengin.GetMiddleware())

	var bodyReadInHandler string
	router.POST("/route", func(c *gin.Context) {
		bodyBytes, err := io.ReadAll(c.Request.Body)
		require.NoError(t, err, "Should be able to read raw body after form parsing in middleware")
		bodyReadInHandler = string(bodyBytes)
		c.String(200, "ok")
	})

	originalBody := "username=bob&password=secret"
	r := httptest.NewRequest("POST", "/route", strings.NewReader(originalBody))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)

	assert.Equal(t, originalBody, bodyReadInHandler)
	assert.Equal(t, 200, w.Code)
}

func TestMiddlewareCallsOnPostRequest(t *testing.T) {
	router := gin.New()
	router.ContextWithFallback = true
	router.Use(zengin.GetMiddleware())

	router.GET("/route/:id", func(c *gin.Context) {
	})

	r := httptest.NewRequest("GET", "/route/foo?query=value", http.NoBody)
	w := httptest.NewRecorder()

	agent.Stats().GetAndClear()

	router.ServeHTTP(w, r)

	require.Eventually(t, func() bool {
		stats := agent.Stats().GetAndClear()
		return stats.Requests.Total == 1
	}, 100*time.Millisecond, 10*time.Millisecond)
}

func TestMiddlewareCallsOnPostRequestOnPanic(t *testing.T) {
	agent.Stats().GetAndClear()

	router := gin.Default()
	router.ContextWithFallback = true
	router.Use(zengin.GetMiddleware())

	router.GET("/route/:id", func(c *gin.Context) {
		panic("error")
	})

	r := httptest.NewRequest("GET", "/route/foo?query=value", http.NoBody)
	w := httptest.NewRecorder()

	agent.Stats().GetAndClear()

	router.ServeHTTP(w, r)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		stats := agent.Stats().GetAndClear()
		require.Equal(c, 1, stats.Requests.Total)
	}, 100*time.Millisecond, 10*time.Millisecond)
}

func TestMiddlewareNestedRouters(t *testing.T) {
	t.Run("nested groups with multiple params", func(t *testing.T) {
		router := gin.New()
		router.ContextWithFallback = true
		router.Use(zengin.GetMiddleware())

		// Create nested groups with pattern like /route/:id/subrouter/:anotherid
		routeGroup := router.Group("/route/:id")
		{
			routeGroup.GET("/subrouter/:anotherid", func(c *gin.Context) {
				ctx := request.GetContext(c)
				require.NotNil(t, ctx, "request context should be set")

				assert.Equal(t, "gin", ctx.Source)
				assert.Equal(t, "/route/:id/subrouter/:anotherid", ctx.Route)
				assert.Equal(t, "123", ctx.RouteParams["id"])
				assert.Equal(t, "456", ctx.RouteParams["anotherid"])
			})
		}

		r := httptest.NewRequest("GET", "/route/123/subrouter/456", http.NoBody)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("deeply nested groups", func(t *testing.T) {
		router := gin.New()
		router.ContextWithFallback = true
		router.Use(zengin.GetMiddleware())

		// Three levels of nesting
		apiGroup := router.Group("/api/:version")
		{
			usersGroup := apiGroup.Group("/users/:userid")
			{
				usersGroup.GET("/posts/:postid", func(c *gin.Context) {
					ctx := request.GetContext(c)
					require.NotNil(t, ctx, "request context should be set")

					assert.Equal(t, "gin", ctx.Source)
					assert.Equal(t, "/api/:version/users/:userid/posts/:postid", ctx.Route)
					assert.Equal(t, "v1", ctx.RouteParams["version"])
					assert.Equal(t, "user123", ctx.RouteParams["userid"])
					assert.Equal(t, "post456", ctx.RouteParams["postid"])
				})
			}
		}

		r := httptest.NewRequest("GET", "/api/v1/users/user123/posts/post456", http.NoBody)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}
