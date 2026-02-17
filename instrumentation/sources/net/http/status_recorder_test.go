//go:build !integration

package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStatusRecorder_WriteHeader(t *testing.T) {
	t.Run("captures status code", func(t *testing.T) {
		r := &statusRecorder{writer: httptest.NewRecorder()}
		r.WriteHeader(http.StatusNotFound)
		assert.Equal(t, http.StatusNotFound, r.statusCode)
	})

	t.Run("captures first status code only", func(t *testing.T) {
		r := &statusRecorder{writer: httptest.NewRecorder()}
		r.WriteHeader(http.StatusNotFound)
		r.WriteHeader(http.StatusInternalServerError)
		assert.Equal(t, http.StatusNotFound, r.statusCode)
	})

	t.Run("passes through to underlying writer", func(t *testing.T) {
		underlying := httptest.NewRecorder()
		r := &statusRecorder{writer: underlying}
		r.WriteHeader(http.StatusCreated)
		assert.Equal(t, http.StatusCreated, underlying.Code)
	})
}

func TestStatusRecorder_Write(t *testing.T) {
	t.Run("defaults to 200 on write", func(t *testing.T) {
		r := &statusRecorder{writer: httptest.NewRecorder()}
		_, _ = r.Write([]byte("hello"))
		assert.Equal(t, http.StatusOK, r.statusCode)
	})

	t.Run("write before writeheader sets 200", func(t *testing.T) {
		r := &statusRecorder{writer: httptest.NewRecorder()}
		_, _ = r.Write([]byte("hello"))
		r.WriteHeader(http.StatusNotFound)
		assert.Equal(t, http.StatusOK, r.statusCode)
	})

	t.Run("passes through to underlying writer", func(t *testing.T) {
		underlying := httptest.NewRecorder()
		r := &statusRecorder{writer: underlying}
		_, _ = r.Write([]byte("body"))
		assert.Equal(t, "body", underlying.Body.String())
	})
}

func TestStatusRecorder_Header(t *testing.T) {
	underlying := httptest.NewRecorder()
	r := &statusRecorder{writer: underlying}
	r.Header().Set("X-Custom", "value")
	assert.Equal(t, "value", underlying.Result().Header.Get("X-Custom"))
}

func TestStatusRecorder_Unwrap(t *testing.T) {
	underlying := httptest.NewRecorder()
	r := &statusRecorder{writer: underlying}
	assert.Same(t, underlying, r.Unwrap())
}

func TestStatusRecorder_ZeroStatus(t *testing.T) {
	r := &statusRecorder{}
	assert.Equal(t, 0, r.statusCode)
}
