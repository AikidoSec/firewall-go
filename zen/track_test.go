package zen_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTrackRequestContext(remoteAddr string) context.Context {
	req, _ := http.NewRequest("GET", "http://example.com/test", http.NoBody)
	return request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/test",
		RemoteAddress: &remoteAddr,
	})
}

func setupTrackServer(t *testing.T, captured *cloud.CustomEvent) *httptest.Server {
	t.Helper()
	eventReceived := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, captured)
		w.WriteHeader(http.StatusOK)
		eventReceived <- struct{}{}
	}))
	t.Cleanup(server.Close)

	client := cloud.NewClient(&cloud.ClientConfig{
		Token:            "test-token",
		RealtimeEndpoint: server.URL,
	})
	original := agent.GetCloudClient()
	agent.SetCloudClient(client)
	t.Cleanup(func() { agent.SetCloudClient(original) })

	return server
}

func TestTrack(t *testing.T) {
	t.Run("sends event with name and ip when no user set", func(t *testing.T) {
		var captured cloud.CustomEvent
		setupTrackServer(t, &captured)

		ctx := newTrackRequestContext("1.2.3.4")
		zen.Track(ctx, "user.login", nil)

		assert.Eventually(t, func() bool { return captured.Name != "" }, time.Second, 10*time.Millisecond)
		assert.Equal(t, "user.login", captured.Name)
		assert.Equal(t, "1.2.3.4", captured.IPAddress)
		assert.Empty(t, captured.UserID)
	})

	t.Run("includes user id when user is set on context", func(t *testing.T) {
		var captured cloud.CustomEvent
		setupTrackServer(t, &captured)

		ctx := newTrackRequestContext("1.2.3.4")
		ctx, err := zen.SetUser(ctx, "user-abc", "Alice")
		require.NoError(t, err)

		zen.Track(ctx, "user.login", nil)

		assert.Eventually(t, func() bool { return captured.Name != "" }, time.Second, 10*time.Millisecond)
		assert.Equal(t, "user.login", captured.Name)
		assert.Equal(t, "user-abc", captured.UserID)
		assert.Equal(t, "1.2.3.4", captured.IPAddress)
	})

	t.Run("no-ops when event name is empty", func(t *testing.T) {
		requestCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(server.Close)

		client := cloud.NewClient(&cloud.ClientConfig{
			Token:            "test-token",
			RealtimeEndpoint: server.URL,
		})
		original := agent.GetCloudClient()
		agent.SetCloudClient(client)
		t.Cleanup(func() { agent.SetCloudClient(original) })

		ctx := newTrackRequestContext("1.2.3.4")
		zen.Track(ctx, "", nil)

		time.Sleep(50 * time.Millisecond)
		assert.Equal(t, 0, requestCount)
	})

	t.Run("no-ops when context has no request", func(t *testing.T) {
		requestCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(server.Close)

		client := cloud.NewClient(&cloud.ClientConfig{
			Token:            "test-token",
			RealtimeEndpoint: server.URL,
		})
		original := agent.GetCloudClient()
		agent.SetCloudClient(client)
		t.Cleanup(func() { agent.SetCloudClient(original) })

		zen.Track(context.Background(), "user.login", nil)

		time.Sleep(50 * time.Millisecond)
		assert.Equal(t, 0, requestCount)
	})

	t.Run("sends metadata when provided", func(t *testing.T) {
		var rawCapture map[string]any
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &rawCapture)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(server.Close)

		client := cloud.NewClient(&cloud.ClientConfig{
			Token:            "test-token",
			RealtimeEndpoint: server.URL,
		})
		original := agent.GetCloudClient()
		agent.SetCloudClient(client)
		t.Cleanup(func() { agent.SetCloudClient(original) })

		ctx := newTrackRequestContext("1.2.3.4")
		zen.Track(ctx, "user.login", map[string]string{"reason": "otp_failed"})

		assert.Eventually(t, func() bool { return rawCapture["name"] != nil }, time.Second, 10*time.Millisecond)
		meta, ok := rawCapture["metadata"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "otp_failed", meta["reason"])
	})
}
