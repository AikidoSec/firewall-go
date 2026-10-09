package zen_test

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	zenhttp "github.com/AikidoSec/firewall-go/instrumentation/http"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	zenlog "github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/internal/testutil"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func requestContext(t *testing.T) context.Context {
	t.Helper()

	req := httptest.NewRequest("POST", "http://example.com/login", http.NoBody)
	req.Header.Set("User-Agent", "test-agent")
	remoteAddr := "192.168.1.1"
	data := zenhttp.ContextDataFromRequest(req)
	data.Source = "test"
	data.Route = "/login"
	data.RemoteAddress = &remoteAddr
	return request.SetContext(context.Background(), data)
}

func TestTrack(t *testing.T) {
	require.NoError(t, agent.Init(&aikido_types.EnvironmentConfigData{}, &aikido_types.AikidoConfigData{}))
	originalClient := agent.GetCloudClient()
	t.Cleanup(func() { agent.SetCloudClient(originalClient) })

	t.Run("ValidInput", func(t *testing.T) {
		mockClient := testutil.NewMockCloudClient()
		agent.SetCloudClient(mockClient)
		t.Cleanup(func() { agent.SetCloudClient(originalClient) })

		ctx := requestContext(t)

		err := zen.Track(ctx, "user.login_failed")
		require.NoError(t, err)

		select {
		case <-mockClient.CustomEventSent:
		case <-time.After(time.Second):
			t.Fatal("expected custom event to be sent")
		}

		assert.Equal(t, "user.login_failed", mockClient.CapturedCustomEventName)
		assert.Equal(t, "POST", mockClient.CapturedCustomRequest.Method)
		assert.Equal(t, "192.168.1.1", mockClient.CapturedCustomRequest.IPAddress)
		assert.Equal(t, "test-agent", mockClient.CapturedCustomRequest.UserAgent)
		assert.Equal(t, "test", mockClient.CapturedCustomRequest.Source)
		assert.Equal(t, "/login", mockClient.CapturedCustomRequest.Route)
		assert.Empty(t, mockClient.CapturedCustomRequest.URL, "custom events should not include the request URL")
		assert.Nil(t, mockClient.CapturedCustomUser, "user should be nil when SetUser was not called")
	})

	t.Run("BypassedIP", func(t *testing.T) {
		zen.ResetTrackWarnOnce()
		mockClient := testutil.NewMockCloudClient()
		agent.SetCloudClient(mockClient)
		config.UpdateServiceConfig(&aikido_types.CloudConfigData{BypassedIPs: []string{"192.168.1.1"}}, nil)
		origLogger := zenlog.Logger()
		var logs bytes.Buffer
		zenlog.SetLogger(slog.New(slog.NewTextHandler(&logs, nil)))
		t.Cleanup(func() {
			config.UpdateServiceConfig(&aikido_types.CloudConfigData{}, nil)
			agent.SetCloudClient(originalClient)
			zenlog.SetLogger(origLogger)
		})

		ctx := requestContext(t)
		require.True(t, request.IsBypassed(ctx))
		require.NoError(t, zen.Track(ctx, "user.login_failed"))

		select {
		case <-mockClient.CustomEventSent:
			t.Fatal("expected no custom event for a bypassed IP")
		case <-time.After(100 * time.Millisecond):
		}
		assert.NotContains(t, logs.String(), "outside of an HTTP request")
	})

	t.Run("WithUser", func(t *testing.T) {
		mockClient := testutil.NewMockCloudClient()
		agent.SetCloudClient(mockClient)
		t.Cleanup(func() { agent.SetCloudClient(originalClient) })

		ctx := requestContext(t)
		ctx, err := zen.SetUser(ctx, "user123", "John Doe")
		require.NoError(t, err)

		err = zen.Track(ctx, "user.login_failed")
		require.NoError(t, err)

		select {
		case <-mockClient.CustomEventSent:
		case <-time.After(time.Second):
			t.Fatal("expected custom event to be sent")
		}

		require.NotNil(t, mockClient.CapturedCustomUser)
		assert.Equal(t, "user123", mockClient.CapturedCustomUser.ID)
		assert.Equal(t, "John Doe", mockClient.CapturedCustomUser.Name)
	})

	t.Run("RateLimitPerRequest", func(t *testing.T) {
		mockClient := testutil.NewMockCloudClient()
		agent.SetCloudClient(mockClient)
		t.Cleanup(func() { agent.SetCloudClient(originalClient) })

		ctx := requestContext(t)
		for i := 0; i < 25; i++ {
			require.NoError(t, zen.Track(ctx, fmt.Sprintf("event.%d", i)))
			select {
			case <-mockClient.CustomEventSent:
			case <-time.After(time.Second):
				t.Fatalf("expected event %d to be sent", i+1)
			}
		}

		for i := 0; i < 2; i++ {
			require.NoError(t, zen.Track(ctx, "over.limit"))
		}
		select {
		case <-mockClient.CustomEventSent:
			t.Fatal("expected events beyond 25 in the same request to be dropped")
		case <-time.After(100 * time.Millisecond):
		}
		require.NoError(t, zen.Track(requestContext(t), "new.request"))
		select {
		case <-mockClient.CustomEventSent:
		case <-time.After(time.Second):
			t.Fatal("expected a separate request to have its own event allowance")
		}
	})

	t.Run("EmptyEventName", func(t *testing.T) {
		ctx := requestContext(t)

		err := zen.Track(ctx, "")
		require.ErrorIs(t, err, zen.ErrEventNameEmpty)
	})

	t.Run("NoRequestContext", func(t *testing.T) {
		zen.ResetTrackWarnOnce()
		mockClient := testutil.NewMockCloudClient()
		agent.SetCloudClient(mockClient)
		t.Cleanup(func() { agent.SetCloudClient(originalClient) })

		err := zen.Track(context.Background(), "user.login_failed")
		require.NoError(t, err)

		select {
		case <-mockClient.CustomEventSent:
			t.Fatal("expected no custom event to be sent outside of a request")
		case <-time.After(100 * time.Millisecond):
		}
	})
}

// ExampleTrack demonstrates how to use Track to record a custom event.
func ExampleTrack() {
	err := zen.Protect()
	if err != nil {
		log.Fatal(err)
	}

	req, _ := http.NewRequest("POST", "/login", http.NoBody)
	ctx := req.Context()

	if err := zen.Track(ctx, "user.login_failed"); err != nil {
		log.Println(err)
		return
	}

	fmt.Println("Event tracked")
	// Output: Event tracked
}
