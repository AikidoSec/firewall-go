//go:build !integration

package http

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatusRecorder(t *testing.T) {
	t.Run("captures status code", func(t *testing.T) {
		recorder := &statusRecorder{
			writer: httptest.NewRecorder(),
		}

		recorder.WriteHeader(http.StatusNotFound)

		assert.Equal(t, http.StatusNotFound, recorder.statusCode)
	})

	t.Run("defaults to 200 on write", func(t *testing.T) {
		recorder := &statusRecorder{
			writer: httptest.NewRecorder(),
		}

		_, _ = recorder.Write([]byte("hello"))

		assert.Equal(t, http.StatusOK, recorder.statusCode)
	})

	t.Run("captures first status code only", func(t *testing.T) {
		recorder := &statusRecorder{
			writer: httptest.NewRecorder(),
		}

		recorder.WriteHeader(http.StatusNotFound)
		recorder.WriteHeader(http.StatusInternalServerError)

		assert.Equal(t, http.StatusNotFound, recorder.statusCode)
	})

	t.Run("write before writeheader sets 200", func(t *testing.T) {
		recorder := &statusRecorder{
			writer: httptest.NewRecorder(),
		}

		_, _ = recorder.Write([]byte("hello"))
		recorder.WriteHeader(http.StatusNotFound)

		assert.Equal(t, http.StatusOK, recorder.statusCode)
	})

	t.Run("passes through to underlying writer", func(t *testing.T) {
		underlying := httptest.NewRecorder()
		recorder := &statusRecorder{
			writer: underlying,
		}

		recorder.WriteHeader(http.StatusCreated)
		_, _ = recorder.Write([]byte("created"))

		assert.Equal(t, http.StatusCreated, underlying.Code)
		assert.Equal(t, "created", underlying.Body.String())
	})
}

func TestMiddlewareAddsContext(t *testing.T) {
	handler := Middleware(func(w http.ResponseWriter, r *http.Request) {
		ctx := request.GetContext(r.Context())
		require.NotNil(t, ctx, "request context should be set")

		assert.Equal(t, "http.ServeMux", ctx.Source)
		assert.Equal(t, "/route", ctx.Route)
		assert.Equal(t, map[string][]string{
			"query": {"value"},
		}, ctx.Query)
	})

	r := httptest.NewRequest("GET", "/route?query=value", http.NoBody)
	w := httptest.NewRecorder()

	handler(w, r)
}

func TestMiddlewareGLSFallback(t *testing.T) {
	handler := Middleware(func(w http.ResponseWriter, r *http.Request) {
		// Test that we can get context using context.Background() (should fallback to GLS)
		ctx := request.GetContext(context.Background())
		require.NotNil(t, ctx, "request context should be set via GLS fallback")

		assert.Equal(t, "http.ServeMux", ctx.Source)
		assert.Equal(t, "/route", ctx.Route)
	})

	r := httptest.NewRequest("GET", "/route", http.NoBody)
	w := httptest.NewRecorder()

	handler(w, r)
}

func TestMiddlewarePreservesBodyForJSON(t *testing.T) {
	var bodyReadInHandler string
	handler := Middleware(func(w http.ResponseWriter, r *http.Request) {
		var data map[string]any
		err := json.NewDecoder(r.Body).Decode(&data)
		require.NoError(t, err, "Should be able to decode JSON after middleware")

		bodyReadInHandler = data["username"].(string)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(data)
	})

	jsonBody := `{"username":"bob","email":"bob@example.com"}`
	r := httptest.NewRequest("POST", "/route", strings.NewReader(jsonBody))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, r)

	assert.Equal(t, "bob", bodyReadInHandler)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMiddlewarePreservesBodyForURLEncoded(t *testing.T) {
	var bodyReadInHandler string
	handler := Middleware(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)
		bodyReadInHandler = r.FormValue("username")
		w.WriteHeader(http.StatusOK)
	})

	formData := "username=bob&password=secret"
	r := httptest.NewRequest("POST", "/route", strings.NewReader(formData))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler(w, r)

	assert.Equal(t, "bob", bodyReadInHandler)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMiddlewarePreservesBodyForMultipart(t *testing.T) {
	var fieldReadInHandler string
	handler := Middleware(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseMultipartForm(32 << 20)
		require.NoError(t, err)
		fieldReadInHandler = r.FormValue("field1")
		w.WriteHeader(http.StatusOK)
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

	handler(w, r)

	assert.Equal(t, "value1", fieldReadInHandler)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMiddlewarePreservesBodyForRawReadAfterFormParsing(t *testing.T) {
	var bodyReadInHandler string
	handler := Middleware(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err, "Should be able to read raw body after form parsing in middleware")
		bodyReadInHandler = string(bodyBytes)
		w.WriteHeader(http.StatusOK)
	})

	originalBody := "username=bob&password=secret"
	r := httptest.NewRequest("POST", "/route", strings.NewReader(originalBody))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler(w, r)

	assert.Equal(t, originalBody, bodyReadInHandler)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestExtractRouteParams(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		path     string
		expected map[string]string
	}{
		{
			name:     "single parameter",
			pattern:  "/users/{id}",
			path:     "/users/123",
			expected: map[string]string{"id": "123"},
		},
		{
			name:     "multiple parameters",
			pattern:  "/posts/{postId}/comments/{commentId}",
			path:     "/posts/456/comments/789",
			expected: map[string]string{"postId": "456", "commentId": "789"},
		},
		{
			name:     "no parameters",
			pattern:  "/users",
			path:     "/users",
			expected: map[string]string{},
		},
		{
			name:     "parameter with trailing path",
			pattern:  "/api/{version}/users",
			path:     "/api/v1/users",
			expected: map[string]string{"version": "v1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc(tt.pattern, func(w http.ResponseWriter, r *http.Request) {})

			req := httptest.NewRequest("GET", tt.path, http.NoBody)
			w := httptest.NewRecorder()

			mux.ServeHTTP(w, req)

			result := extractRouteParams(req, tt.pattern)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMiddlewareCallsOnPostRequest(t *testing.T) {
	agent.Stats().GetAndClear()

	handler := Middleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest("GET", "/route?query=value", http.NoBody)
	w := httptest.NewRecorder()

	agent.Stats().GetAndClear()

	handler(w, r)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		stats := agent.Stats().GetAndClear()
		require.Equal(c, 1, stats.Requests.Total)
	}, 100*time.Millisecond, 10*time.Millisecond)
}
