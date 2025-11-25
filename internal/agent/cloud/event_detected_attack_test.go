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

func TestClient_SendAttackDetectedEvent(t *testing.T) {
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
		URL:       "/api/test",
		Source:    "test",
		Route:     "/api/test",
	}

	attackDetails := aikido_types.AttackDetails{
		Kind:      "sql_injection",
		Operation: "query",
		Module:    "database",
		Blocked:   true,
		Source:    "body",
		Path:      "query",
		Stack:     "stack trace",
		Payload:   "'; DROP TABLE users; --",
		Metadata: map[string]string{
			"key": "value",
		},
		User: &aikido_types.User{
			ID:            "user123",
			Name:          "test-user",
			LastIpAddress: "192.168.1.1",
			FirstSeenAt:   1000,
			LastSeenAt:    2000,
		},
	}

	t.Run("sends event successfully when rate limit allows", func(t *testing.T) {
		resetAttackDetectedEvents()

		var capturedPayload DetectedAttackEvent
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

		client.SendAttackDetectedEvent(agentInfo, requestInfo, attackDetails)

		// Verify the event structure
		assert.Equal(t, "detected_attack", capturedPayload.Type, "should have correct type")
		assert.Equal(t, agentInfo, capturedPayload.Agent, "should include agent info")
		assert.Equal(t, requestInfo, capturedPayload.Request, "should include request info")
		assert.Equal(t, attackDetails, capturedPayload.Attack, "should include attack details")

		// Verify timestamp is within a reasonable range (5 seconds)
		eventTime := time.UnixMilli(capturedPayload.Time)
		assert.WithinDuration(t, time.Now(), eventTime, 5*time.Second, "timestamp should be within 5 seconds of current time")
	})

	t.Run("does not send event when rate limit is exceeded", func(t *testing.T) {
		resetAttackDetectedEvents()

		requestCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := &Client{
			httpClient:  &http.Client{Timeout: 30 * time.Second},
			apiEndpoint: server.URL,
			token:       "test-token",
		}

		// Fill up the rate limit
		for i := 0; i < maxAttackDetectedEventsPerInterval; i++ {
			client.SendAttackDetectedEvent(agentInfo, requestInfo, attackDetails)
		}

		initialRequestCount := requestCount

		// This call should not send because rate limit is exceeded
		client.SendAttackDetectedEvent(agentInfo, requestInfo, attackDetails)

		// Verify no additional request was made
		assert.Equal(t, initialRequestCount, requestCount, "should not send event when rate limit is exceeded")
	})

	t.Run("handles HTTP errors gracefully", func(t *testing.T) {
		resetAttackDetectedEvents()

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
		client.SendAttackDetectedEvent(agentInfo, requestInfo, attackDetails)

		// Verify the server was called (event was attempted)
		assert.Equal(t, 1, requestCount, "should have attempted to send event to server")
	})

	t.Run("handles network errors gracefully", func(t *testing.T) {
		resetAttackDetectedEvents()

		// Create a server that closes immediately to simulate connection error
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		serverURL := server.URL
		server.Close()

		client := &Client{
			httpClient:  &http.Client{Timeout: 30 * time.Second},
			apiEndpoint: serverURL,
			token:       "test-token",
		}

		// Should not panic, just log error and return
		client.SendAttackDetectedEvent(agentInfo, requestInfo, attackDetails)

		// Verify the event was still attempted (rate limit was incremented)
		attackDetectedEventsSentAtMutex.Lock()
		count := len(attackDetectedEventsSentAt)
		attackDetectedEventsSentAtMutex.Unlock()
		assert.Equal(t, 1, count, "should have attempted to send event")
	})

	t.Run("uses correct endpoint and route", func(t *testing.T) {
		resetAttackDetectedEvents()

		var capturedPath string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedPath = r.URL.Path
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		}))
		defer server.Close()

		client := &Client{
			httpClient:  &http.Client{Timeout: 30 * time.Second},
			apiEndpoint: server.URL,
			token:       "test-token",
		}

		client.SendAttackDetectedEvent(agentInfo, requestInfo, attackDetails)

		assert.Equal(t, "/api/runtime/events", capturedPath, "should use correct API route")
	})

	t.Run("includes all event fields correctly", func(t *testing.T) {
		resetAttackDetectedEvents()

		var capturedPayload DetectedAttackEvent
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &capturedPayload)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		}))
		defer server.Close()

		client := &Client{
			httpClient:  &http.Client{Timeout: 30 * time.Second},
			apiEndpoint: server.URL,
			token:       "test-token",
		}

		client.SendAttackDetectedEvent(agentInfo, requestInfo, attackDetails)

		// Verify all fields are populated correctly
		assert.Equal(t, "detected_attack", capturedPayload.Type)
		assert.Equal(t, agentInfo.Hostname, capturedPayload.Agent.Hostname)
		assert.Equal(t, agentInfo.Version, capturedPayload.Agent.Version)
		assert.Equal(t, requestInfo.Method, capturedPayload.Request.Method)
		assert.Equal(t, requestInfo.URL, capturedPayload.Request.URL)
		assert.Equal(t, attackDetails.Kind, capturedPayload.Attack.Kind)
		assert.Equal(t, attackDetails.Blocked, capturedPayload.Attack.Blocked)
		assert.Equal(t, attackDetails.Payload, capturedPayload.Attack.Payload)
		require.NotNil(t, capturedPayload.Attack.User, "user should not be nil")
		assert.Equal(t, attackDetails.User.ID, capturedPayload.Attack.User.ID)

		eventTime := time.UnixMilli(capturedPayload.Time)
		assert.WithinDuration(t, time.Now(), eventTime, 5*time.Second, "timestamp should be within 5 seconds of current time")
	})
}
