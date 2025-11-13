//go:build !integration

package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
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
