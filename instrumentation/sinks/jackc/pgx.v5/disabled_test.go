//go:build !integration

package pgx_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/instrumentation/sinks/jackc/pgx.v5"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/internal/testutil"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/require"
)

func TestExamineContext_Disabled(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()
	originalBlocking := config.IsBlockingEnabled()
	config.SetBlocking(true)
	defer func() {
		config.SetBlocking(originalBlocking)
		agent.SetCloudClient(originalClient)
	}()

	mockClient := testutil.NewMockCloudClient()
	agent.SetCloudClient(mockClient)

	req := httptest.NewRequest("GET", "/test?query=1%27%20OR%201%3D1", nil)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/test",
		RemoteAddress: &ip,
	})

	zen.SetDisabled(true)
	require.True(t, zen.IsDisabled(), "zen should be disabled")

	maliciousQuery := "SELECT * FROM users WHERE id = '1' OR 1=1"

	err := pgx.ExamineContext(ctx, maliciousQuery, "github.com/jackc/pgx/v5.Query")

	require.NoError(t, err, "ExamineContext should return early with no error when zen is disabled")

	select {
	case <-mockClient.AttackDetectedEventSent:
		t.Fatal("No attack should be detected when zen is disabled")
	case <-time.After(50 * time.Millisecond):
		// Expected: no attack detected
	}
}

func TestExamineContext_NotLoaded(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	originalLoaded := config.IsZenLoaded()
	defer func() {
		zen.SetDisabled(originalDisabled)
		config.SetZenLoaded(originalLoaded)
	}()

	// Set state: not disabled, but not loaded
	zen.SetDisabled(false)
	config.SetZenLoaded(false)

	originalClient := agent.GetCloudClient()
	originalBlocking := config.IsBlockingEnabled()
	config.SetBlocking(true)
	defer func() {
		config.SetBlocking(originalBlocking)
		agent.SetCloudClient(originalClient)
	}()

	mockClient := testutil.NewMockCloudClient()
	agent.SetCloudClient(mockClient)

	req := httptest.NewRequest("GET", "/test?query=1%27%20OR%201%3D1", nil)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/test",
		RemoteAddress: &ip,
	})

	maliciousQuery := "SELECT * FROM users WHERE id = '1' OR 1=1"

	err := pgx.ExamineContext(ctx, maliciousQuery, "github.com/jackc/pgx/v5.Query")

	require.NoError(t, err, "ExamineContext should return early with no error when zen is not loaded")

	select {
	case <-mockClient.AttackDetectedEventSent:
		t.Fatal("No attack should be detected when zen is not loaded")
	case <-time.After(50 * time.Millisecond):
		// Expected: no attack detected
	}
}
