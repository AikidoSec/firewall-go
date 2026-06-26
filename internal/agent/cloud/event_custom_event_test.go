package cloud

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_SendCustomEvent(t *testing.T) {
	t.Run("sends event to realtime endpoint with correct structure", func(t *testing.T) {
		var captured CustomEvent
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "/api/runtime/events", r.URL.Path)
			assert.Equal(t, "test-token", r.Header.Get("Authorization"))
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(body, &captured))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := &Client{
			httpClient:       &http.Client{Timeout: 30 * time.Second},
			realtimeEndpoint: server.URL,
			token:            "test-token",
		}

		client.SendCustomEvent(CustomEvent{
			Name:      "user.login",
			UserID:    "user-123",
			IPAddress: "1.2.3.4",
		})

		assert.Equal(t, "user.login", captured.Name)
		assert.Equal(t, "user-123", captured.UserID)
		assert.Equal(t, "1.2.3.4", captured.IPAddress)
	})

	t.Run("omits empty fields from payload", func(t *testing.T) {
		var rawCapture map[string]any
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &rawCapture)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := &Client{
			httpClient:       &http.Client{Timeout: 30 * time.Second},
			realtimeEndpoint: server.URL,
			token:            "test-token",
		}

		client.SendCustomEvent(CustomEvent{Name: "user.login"})

		assert.Equal(t, "user.login", rawCapture["name"])
		_, hasUserID := rawCapture["userId"]
		assert.False(t, hasUserID, "userId should be omitted when empty")
		_, hasMetadata := rawCapture["metadata"]
		assert.False(t, hasMetadata, "metadata should be omitted when nil")
	})

	t.Run("handles HTTP errors gracefully", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := &Client{
			httpClient:       &http.Client{Timeout: 30 * time.Second},
			realtimeEndpoint: server.URL,
			token:            "test-token",
		}

		assert.NotPanics(t, func() {
			client.SendCustomEvent(CustomEvent{Name: "user.login"})
		})
	})
}
