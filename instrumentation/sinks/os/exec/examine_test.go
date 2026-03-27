//go:build !integration

package exec_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/instrumentation/sinks/os/exec"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/internal/testutil"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExamine_TracksOperationStats(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()
	defer agent.SetCloudClient(originalClient)

	mockClient := testutil.NewMockCloudClient()
	agent.SetCloudClient(mockClient)

	req := httptest.NewRequest("GET", "/test", nil)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/test",
		RemoteAddress: &ip,
	})

	// Clear stats before test
	agent.Stats().GetAndClear()

	// Execute shell commands - both should be tracked
	_ = exec.Examine(ctx, "os/exec.Cmd.Run", []string{"sh", "-c", "echo hello"})
	_ = exec.Examine(ctx, "os/exec.Cmd.Start", []string{"bash", "-c", "ls"})

	// Get stats and verify operations were tracked
	stats := agent.Stats().GetAndClear()
	require.Contains(t, stats.Operations, "os/exec.Cmd.Run")
	require.Contains(t, stats.Operations, "os/exec.Cmd.Start")

	require.Equal(t, 1, stats.Operations["os/exec.Cmd.Run"].Total, "Run should be called once")
	require.Equal(t, 1, stats.Operations["os/exec.Cmd.Start"].Total, "Start should be called once")
}

func TestExamine_ReportsModuleName(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()
	defer agent.SetCloudClient(originalClient)

	originalBlocking := config.IsBlockingEnabled()
	defer config.SetBlocking(originalBlocking)
	config.SetBlocking(true)

	mockClient := testutil.NewMockCloudClient()
	agent.SetCloudClient(mockClient)

	req := httptest.NewRequest("GET", "/test?cmd=ls%20.", nil)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/test",
		RemoteAddress: &ip,
	})

	_ = exec.Examine(ctx, "os/exec.Cmd.Run", []string{"sh", "-c", "ls ."})

	select {
	case <-mockClient.AttackDetectedEventSent:
		assert.Equal(t, "os/exec", mockClient.CapturedAttack.Module)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for attack event")
	}
}
