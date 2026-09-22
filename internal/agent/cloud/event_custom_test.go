package cloud

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_SendCustomEvent(t *testing.T) {
	agentInfo := AgentInfo{
		DryMode:   false,
		Hostname:  "test-host",
		Version:   "1.0.0",
		IPAddress: "127.0.0.1",
		OS: OSInfo{
			Name:    "linux",
			Version: "5.4.0",
		},
		Platform: PlatformInfo{
			Name:    "go",
			Version: "1.24",
		},
		Packages: map[string]string{
			"package1": "1.0.0",
		},
	}

	requestInfo := aikido_types.RequestInfo{
		Method:    "POST",
		IPAddress: "192.168.1.1",
		UserAgent: "test-agent",
		URL:       "/api/login",
		Source:    "test",
		Route:     "/api/login",
	}

	t.Run("sends event successfully with correct structure", func(t *testing.T) {
		user := &aikido_types.User{ID: "user123", Name: "test-user"}

		var capturedPayload CustomEvent
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method, "should use POST method")
			assert.Equal(t, "/api/runtime/events", r.URL.Path, "should use correct route")
			assert.Equal(t, "test-token", r.Header.Get("Authorization"), "should include authorization header")
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"), "should include content-type header")

			body, err := io.ReadAll(r.Body)
			require.NoError(t, err, "should read request body")
			require.NotEmpty(t, body, "request body should not be empty")

			err = json.Unmarshal(body, &capturedPayload)
			require.NoError(t, err, "should unmarshal JSON payload")

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		}))
		defer server.Close()

		client := &Client{
			httpClient:  &http.Client{Timeout: 30 * time.Second},
			apiEndpoint: server.URL,
			token:       "test-token",
		}

		client.SendCustomEvent(agentInfo, requestInfo, "user.login_failed", user)

		assert.Equal(t, "custom", capturedPayload.Type, "should have correct type")
		assert.Equal(t, "user.login_failed", capturedPayload.Name, "should include event name")
		assert.Equal(t, agentInfo, capturedPayload.Agent, "should include agent info")
		assert.Equal(t, requestInfo, capturedPayload.Request, "should include request info")
		require.NotNil(t, capturedPayload.User, "user should not be nil")
		assert.Equal(t, user.ID, capturedPayload.User.ID)
		assert.Equal(t, user.Name, capturedPayload.User.Name)

		eventTime := time.UnixMilli(capturedPayload.Time)
		assert.WithinDuration(t, time.Now(), eventTime, 5*time.Second, "timestamp should be within 5 seconds of current time")
	})

	t.Run("omits user field when no user is set", func(t *testing.T) {
		var capturedBody map[string]any
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)

			err = json.Unmarshal(body, &capturedBody)
			require.NoError(t, err)

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		}))
		defer server.Close()

		client := &Client{
			httpClient:  &http.Client{Timeout: 30 * time.Second},
			apiEndpoint: server.URL,
			token:       "test-token",
		}

		client.SendCustomEvent(agentInfo, requestInfo, "user.login_failed", nil)

		_, ok := capturedBody["user"]
		assert.False(t, ok, "user field should be omitted entirely when no user is set")
	})

	t.Run("handles HTTP errors gracefully", func(t *testing.T) {
		requestCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := &Client{
			httpClient:  &http.Client{Timeout: 30 * time.Second},
			apiEndpoint: server.URL,
			token:       "test-token",
		}

		// Should not panic, just log error and return
		client.SendCustomEvent(agentInfo, requestInfo, "user.login_failed", nil)

		assert.Equal(t, 1, requestCount, "should have attempted to send event to server")
	})
}
