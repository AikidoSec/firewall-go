package cloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func feedLines(p *sseParser, lines ...string) (sseEvent, bool) {
	var event sseEvent
	var ok bool
	for _, line := range lines {
		event, ok = p.feedLine(line)
	}
	return event, ok
}

func TestSSEParserFeedLine(t *testing.T) {
	t.Run("does not dispatch on non-blank lines", func(t *testing.T) {
		p := &sseParser{}

		_, ok := p.feedLine("event: config-updated")
		assert.False(t, ok)

		_, ok = p.feedLine(`data: {"configUpdatedAt":100}`)
		assert.False(t, ok)
	})

	t.Run("dispatches event with name and data on blank line", func(t *testing.T) {
		p := &sseParser{}
		event, ok := feedLines(p,
			"event: config-updated",
			`data: {"configUpdatedAt":100}`,
			"",
		)

		require.True(t, ok)
		assert.Equal(t, "config-updated", event.name)
		assert.Equal(t, `{"configUpdatedAt":100}`, event.data)
	})

	t.Run("multiple data lines are joined with newlines", func(t *testing.T) {
		p := &sseParser{}
		event, ok := feedLines(p,
			"event: config-updated",
			"data: line one",
			"data: line two",
			"data: line three",
			"",
		)

		require.True(t, ok)
		assert.Equal(t, "config-updated", event.name)
		assert.Equal(t, "line one\nline two\nline three", event.data)
	})

	t.Run("ignores comment lines", func(t *testing.T) {
		p := &sseParser{}
		event, ok := feedLines(p,
			": ping",
			"event: config-updated",
			`data: {"configUpdatedAt":100}`,
			"",
		)

		require.True(t, ok)
		assert.Equal(t, "config-updated", event.name)
		assert.Equal(t, `{"configUpdatedAt":100}`, event.data)
	})

	t.Run("resets state after dispatching", func(t *testing.T) {
		p := &sseParser{}
		feedLines(p, "event: config-updated", `data: {"configUpdatedAt":100}`, "")

		event, ok := feedLines(p, "")

		require.True(t, ok)
		assert.Equal(t, "", event.name)
		assert.Equal(t, "", event.data)
	})
}

func TestSubscribeToConfigUpdates(t *testing.T) {
	t.Run("connects with auth header and receives events, ignoring pings", func(t *testing.T) {
		var receivedAuth string
		release := make(chan struct{})

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			flusher := w.(http.Flusher)

			w.Write([]byte(": ping\n\n"))
			flusher.Flush()

			w.Write([]byte("event: config-updated\ndata: {\"configUpdatedAt\":100}\n\n"))
			flusher.Flush()

			<-release
		}))
		defer server.Close()

		client := &Client{realtimeEndpoint: server.URL, token: "my-secret-token"}

		updates := make(chan int64, 1)
		done := make(chan error, 1)
		go func() {
			done <- client.SubscribeToConfigUpdates(context.Background(), func(configUpdatedAt int64) {
				updates <- configUpdatedAt
			})
		}()

		select {
		case v := <-updates:
			assert.Equal(t, int64(100), v)
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for config update")
		}

		assert.Equal(t, "my-secret-token", receivedAuth)

		close(release)

		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for SubscribeToConfigUpdates to return")
		}
	})

	t.Run("returns nil when server closes the connection cleanly", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
		}))
		defer server.Close()

		client := &Client{realtimeEndpoint: server.URL, token: "test-token"}

		err := client.SubscribeToConfigUpdates(context.Background(), func(int64) {})
		assert.NoError(t, err)
	})

	t.Run("returns ErrNotRetryable on 401", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		client := &Client{realtimeEndpoint: server.URL, token: "test-token"}

		err := client.SubscribeToConfigUpdates(context.Background(), func(int64) {})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNotRetryable)
	})

	t.Run("returns a retryable error on 500", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := &Client{realtimeEndpoint: server.URL, token: "test-token"}

		err := client.SubscribeToConfigUpdates(context.Background(), func(int64) {})
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrNotRetryable)
	})

	t.Run("returns an error after an idle read timeout", func(t *testing.T) {
		original := sseReadTimeout
		sseReadTimeout = 100 * time.Millisecond
		t.Cleanup(func() { sseReadTimeout = original })

		release := make(chan struct{})

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-release
		}))
		defer server.Close()
		defer close(release)

		client := &Client{realtimeEndpoint: server.URL, token: "test-token"}

		done := make(chan error, 1)
		go func() {
			done <- client.SubscribeToConfigUpdates(context.Background(), func(int64) {})
		}()

		select {
		case err := <-done:
			assert.Error(t, err)
		case <-time.After(2 * time.Second):
			t.Fatal("expected SubscribeToConfigUpdates to return after idle timeout")
		}
	})
}
