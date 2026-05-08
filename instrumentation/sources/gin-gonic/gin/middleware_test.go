//go:build !integration

package gin_test

import (
	"bytes"
	"context"
	"fmt"
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
	gin.SetMode(gin.ReleaseMode)

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

func TestMiddlewareSetsIPInContext(t *testing.T) {
	router := gin.New()
	router.ContextWithFallback = true
	router.Use(zengin.GetMiddleware())

	router.GET("/route", func(c *gin.Context) {
		ctx := request.GetContext(c)
		require.NotNil(t, ctx, "request context should be set")

		assert.Equal(t, "192.168.1.1", ctx.GetIP())
	})

	r := httptest.NewRequest("GET", "/route", http.NoBody)
	r.RemoteAddr = "192.168.1.1:1234"
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
	b.Run("simple", func(b *testing.B) {
		b.Run("plain", func(b *testing.B) {
			router := gin.New()
			router.ContextWithFallback = true
			router.GET("/route", func(c *gin.Context) {})

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					r := httptest.NewRequest("GET", "/route", http.NoBody)
					addBrowserHeaders(r)
					w := httptest.NewRecorder()
					router.ServeHTTP(w, r)
				}
			})
		})

		b.Run("zen", func(b *testing.B) {
			router := gin.New()
			router.ContextWithFallback = true
			router.Use(zengin.GetMiddleware())
			router.GET("/route", func(c *gin.Context) {})

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					r := httptest.NewRequest("GET", "/route", http.NoBody)
					addBrowserHeaders(r)
					w := httptest.NewRecorder()
					router.ServeHTTP(w, r)
				}
			})
		})
	})

	b.Run("json-body", func(b *testing.B) {
		const body = `{"username":"bob","email":"bob@example.com"}`

		b.Run("plain", func(b *testing.B) {
			router := gin.New()
			router.ContextWithFallback = true
			router.POST("/route", func(c *gin.Context) {})

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					r := httptest.NewRequest("POST", "/route", strings.NewReader(body))
					addBrowserHeaders(r)
					r.Header.Set("Content-Type", "application/json")
					w := httptest.NewRecorder()
					router.ServeHTTP(w, r)
				}
			})
		})

		b.Run("zen", func(b *testing.B) {
			router := gin.New()
			router.ContextWithFallback = true
			router.Use(zengin.GetMiddleware())
			router.POST("/route", func(c *gin.Context) {})

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					r := httptest.NewRequest("POST", "/route", strings.NewReader(body))
					addBrowserHeaders(r)
					r.Header.Set("Content-Type", "application/json")
					w := httptest.NewRecorder()
					router.ServeHTTP(w, r)
				}
			})
		})
	})

	b.Run("form-body", func(b *testing.B) {
		const body = "username=bob&password=secret"

		b.Run("plain", func(b *testing.B) {
			router := gin.New()
			router.ContextWithFallback = true
			router.POST("/route", func(c *gin.Context) {})

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					r := httptest.NewRequest("POST", "/route", strings.NewReader(body))
					addBrowserHeaders(r)
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					w := httptest.NewRecorder()
					router.ServeHTTP(w, r)
				}
			})
		})

		b.Run("zen", func(b *testing.B) {
			router := gin.New()
			router.ContextWithFallback = true
			router.Use(zengin.GetMiddleware())
			router.POST("/route", func(c *gin.Context) {})

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					r := httptest.NewRequest("POST", "/route", strings.NewReader(body))
					addBrowserHeaders(r)
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					w := httptest.NewRecorder()
					router.ServeHTTP(w, r)
				}
			})
		})
	})

	b.Run("ip-list", func(b *testing.B) {
		b.Run("plain", func(b *testing.B) {
			router := gin.New()
			router.ContextWithFallback = true
			router.GET("/route", func(c *gin.Context) {})

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					r := httptest.NewRequest("GET", "/route", http.NoBody)
					addBrowserHeaders(r)
					r.RemoteAddr = "192.168.1.1:1234"
					w := httptest.NewRecorder()
					router.ServeHTTP(w, r)
				}
			})
		})

		b.Run("zen", func(b *testing.B) {
			block := true
			config.UpdateServiceConfig(&aikido_types.CloudConfigData{
				Block: &block,
			}, &aikido_types.ListsConfigData{
				BlockedIPAddresses: []aikido_types.IPList{
					{
						Source:      "benchmark",
						Description: "benchmark blocked IPs",
						IPs:         generateIPs(10_000),
					},
				},
			})
			b.Cleanup(func() {
				noBlock := false
				config.UpdateServiceConfig(&aikido_types.CloudConfigData{
					Block: &noBlock,
				}, &aikido_types.ListsConfigData{})
			})

			router := gin.New()
			router.ContextWithFallback = true
			router.Use(zengin.GetMiddleware())
			router.GET("/route", func(c *gin.Context) {})

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					r := httptest.NewRequest("GET", "/route", http.NoBody)
					addBrowserHeaders(r)
					r.RemoteAddr = "192.168.1.1:1234"
					w := httptest.NewRecorder()
					router.ServeHTTP(w, r)
				}
			})
		})
	})

	b.Run("route-params", func(b *testing.B) {
		b.Run("plain", func(b *testing.B) {
			router := gin.New()
			router.ContextWithFallback = true
			router.GET("/users/:id", func(c *gin.Context) {})

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					r := httptest.NewRequest("GET", "/users/123", http.NoBody)
					addBrowserHeaders(r)
					w := httptest.NewRecorder()
					router.ServeHTTP(w, r)
				}
			})
		})

		b.Run("zen", func(b *testing.B) {
			router := gin.New()
			router.ContextWithFallback = true
			router.Use(zengin.GetMiddleware())
			router.GET("/users/:id", func(c *gin.Context) {})

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					r := httptest.NewRequest("GET", "/users/123", http.NoBody)
					addBrowserHeaders(r)
					w := httptest.NewRecorder()
					router.ServeHTTP(w, r)
				}
			})
		})
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

func generateIPs(n int) []string {
	ips := make([]string, n)
	for i := range n {
		ips[i] = fmt.Sprintf("10.%d.%d.%d", (i/65536)%256, (i/256)%256, i%256)
	}
	return ips
}

func addBrowserHeaders(r *http.Request) {
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	r.Header.Set("Accept-Language", "en-US,en;q=0.9")
	r.Header.Set("Accept-Encoding", "gzip, deflate, br")
	r.Header.Set("Connection", "keep-alive")
	r.Header.Set("Cache-Control", "max-age=0")
}
