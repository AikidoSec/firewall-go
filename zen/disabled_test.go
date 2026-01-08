package zen

import (
	"context"
	"net/http"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/stretchr/testify/require"
)

func TestDisabledAPI(t *testing.T) {
	originalDisabled := IsDisabled()
	defer SetDisabled(originalDisabled)

	SetDisabled(true)

	t.Run("IsDisabled returns true", func(t *testing.T) {
		require.True(t, IsDisabled())
	})

	t.Run("SetUser no-ops when disabled", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com/test", nil)
		remoteAddr := "127.0.0.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/test",
			RemoteAddress: &remoteAddr,
		})

		resultCtx, err := SetUser(ctx, "user123", "John Doe")

		require.NoError(t, err)
		require.NotNil(t, resultCtx)

		reqCtx := request.GetContext(resultCtx)
		require.NotNil(t, reqCtx)

		user := reqCtx.GetUser()
		require.Nil(t, user, "User should not be set when zen is disabled")
	})

	t.Run("SetRateLimitGroup no-ops when disabled", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com/test", nil)
		remoteAddr := "127.0.0.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/test",
			RemoteAddress: &remoteAddr,
		})

		resultCtx, err := SetRateLimitGroup(ctx, "group123")

		require.NoError(t, err)
		require.NotNil(t, resultCtx)

		reqCtx := request.GetContext(resultCtx)
		require.NotNil(t, reqCtx)

		group := reqCtx.GetRateLimitGroup()
		require.Empty(t, group, "Rate limit group should not be set when zen is disabled")
	})

	t.Run("ShouldBlockRequest returns nil when disabled", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com/test", nil)
		remoteAddr := "127.0.0.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/test",
			RemoteAddress: &remoteAddr,
		})

		result := ShouldBlockRequest(ctx)

		require.Nil(t, result, "ShouldBlockRequest should return nil when zen is disabled")
	})
}
