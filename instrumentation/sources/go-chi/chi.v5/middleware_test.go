//go:build !integration

package chi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	zenchi "github.com/AikidoSec/firewall-go/instrumentation/sources/go-chi/chi.v5"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/go-chi/chi/v5"
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
	router := chi.NewRouter()
	router.Use(zenchi.GetMiddleware())

	router.Get("/route/{id}", func(w http.ResponseWriter, r *http.Request) {
		ctx := request.GetContext(r.Context())
		require.NotNil(t, ctx, "request context should be set")

		assert.Equal(t, "chi", ctx.Source)
		assert.Equal(t, "/route/{id}", ctx.Route)
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
	router := chi.NewRouter()
	router.Use(zenchi.GetMiddleware())

	router.Get("/route", func(w http.ResponseWriter, r *http.Request) {
		ctx := request.GetContext(r.Context())
		require.NotNil(t, ctx, "request context should be set")

		assert.Equal(t, "192.168.1.1", ctx.GetIP())
	})

	r := httptest.NewRequest("GET", "/route", http.NoBody)
	r.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)
}

func TestMiddlewareGLSFallback(t *testing.T) {
	router := chi.NewRouter()
	router.Use(zenchi.GetMiddleware())

	router.Get("/route", func(w http.ResponseWriter, r *http.Request) {
		// Test that we can get context using context.Background() (should fallback to GLS)
		ctx := request.GetContext(context.Background())
		require.NotNil(t, ctx, "request context should be set via GLS fallback")

		assert.Equal(t, "chi", ctx.Source)
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

	router := chi.NewRouter()
	router.Use(zenchi.GetMiddleware())

	router.Get("/route", func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("request should have been blocked")
	})

	router.Get("/allowed-route", func(w http.ResponseWriter, r *http.Request) {})

	router.Get("/admin", func(w http.ResponseWriter, r *http.Request) {})

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
	router := chi.NewRouter()
	router.Use(zenchi.GetMiddleware())

	router.Get("/route", func(w http.ResponseWriter, r *http.Request) {})

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r := httptest.NewRequest("GET", "/route", http.NoBody)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
		}
	})
}

func TestMiddlewarePreservesBodyForJSON(t *testing.T) {
	router := chi.NewRouter()
	router.Use(zenchi.GetMiddleware())

	var bodyReadInHandler string
	router.Post("/route", func(w http.ResponseWriter, r *http.Request) {
		var data map[string]any
		err := json.NewDecoder(r.Body).Decode(&data)
		require.NoError(t, err, "Should be able to decode JSON after middleware")

		bodyReadInHandler = data["username"].(string)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(data)
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
	router := chi.NewRouter()
	router.Use(zenchi.GetMiddleware())

	var bodyReadInHandler string
	router.Post("/route", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)
		username := r.FormValue("username")
		bodyReadInHandler = username
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
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
	router := chi.NewRouter()
	router.Use(zenchi.GetMiddleware())

	var fieldReadInHandler string
	router.Post("/route", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseMultipartForm(32 << 20)
		require.NoError(t, err)
		field1 := r.FormValue("field1")
		fieldReadInHandler = field1
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
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
	router := chi.NewRouter()
	router.Use(zenchi.GetMiddleware())

	var bodyReadInHandler string
	router.Post("/route", func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err, "Should be able to read raw body after form parsing in middleware")
		bodyReadInHandler = string(bodyBytes)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
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
	agent.Stats().GetAndClear()

	router := chi.NewRouter()
	router.Use(zenchi.GetMiddleware())

	router.Get("/route", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest("GET", "/route?query=value", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		stats := agent.Stats().GetAndClear()
		require.Equal(c, 1, stats.Requests.Total)
	}, 100*time.Millisecond, 10*time.Millisecond)
}

func TestMiddlewareNestedRouters(t *testing.T) {
	t.Run("mounted sub-router", func(t *testing.T) {
		router := chi.NewRouter()
		router.Use(zenchi.GetMiddleware())

		// Create a sub-router with NewRouter
		apiRouter := chi.NewRouter()

		// Instrumentation would automatically add middleware again
		apiRouter.Use(zenchi.GetMiddleware())

		apiRouter.Get("/articles/{date}-{slug}", func(w http.ResponseWriter, r *http.Request) {
			ctx := request.GetContext(r.Context())
			require.NotNil(t, ctx, "request context should be set")

			assert.Equal(t, "chi", ctx.Source)
			assert.Equal(t, "/api/{version}/articles/{date}-{slug}", ctx.Route)
			assert.Equal(t, "20170116", ctx.RouteParams["date"])
			assert.Equal(t, "hello-world", ctx.RouteParams["slug"])
			assert.Equal(t, "v1", ctx.RouteParams["version"])
		})

		router.Mount("/api/{version}", apiRouter)

		r := httptest.NewRequest("GET", "/api/v1/articles/20170116-hello-world", http.NoBody)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("route sub-router", func(t *testing.T) {
		router := chi.NewRouter()
		router.Use(zenchi.GetMiddleware())

		// Use Route method to create nested routers with pattern like /route/{id}/subrouter/{anotherid}
		router.Route("/route/{id}", func(r chi.Router) {
			r.Get("/subrouter/{anotherid}", func(w http.ResponseWriter, r *http.Request) {
				ctx := request.GetContext(r.Context())
				require.NotNil(t, ctx, "request context should be set")

				assert.Equal(t, "chi", ctx.Source)
				assert.Equal(t, "/route/{id}/subrouter/{anotherid}", ctx.Route)
				assert.Equal(t, "123", ctx.RouteParams["id"])
				assert.Equal(t, "456", ctx.RouteParams["anotherid"])
			})
		})

		r := httptest.NewRequest("GET", "/route/123/subrouter/456", http.NoBody)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("group", func(t *testing.T) {
		router := chi.NewRouter()
		router.Use(zenchi.GetMiddleware())

		// Test Group - middleware should be applied within the group
		router.Group(func(r chi.Router) {
			r.Get("/manage/url/{path}", func(w http.ResponseWriter, r *http.Request) {
				ctx := request.GetContext(r.Context())
				require.NotNil(t, ctx, "request context should be set")

				assert.Equal(t, "chi", ctx.Source)
				assert.Equal(t, "/manage/url/{path}", ctx.Route)
				assert.Equal(t, "asset123", ctx.RouteParams["path"])
			})
		})

		r := httptest.NewRequest("GET", "/manage/url/asset123", http.NoBody)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}
