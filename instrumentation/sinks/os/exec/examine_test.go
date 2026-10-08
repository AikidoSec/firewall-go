//go:build !integration

package exec_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	zenhttp "github.com/AikidoSec/firewall-go/instrumentation/http"
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
	data := zenhttp.ContextDataFromRequest(req)
	data.Source = "test"
	data.Route = "/test"
	data.RemoteAddress = &ip
	ctx := request.SetContext(context.Background(), data)

	// Clear stats before test
	agent.Stats().GetAndClear()

	// Execute shell commands - both should be tracked
	_ = exec.Examine(ctx, "os/exec.Cmd.Run", []string{"sh", "-c", "echo hello"}, nil)
	_ = exec.Examine(ctx, "os/exec.Cmd.Start", []string{"bash", "-c", "ls"}, nil)

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
	data := zenhttp.ContextDataFromRequest(req)
	data.Source = "test"
	data.Route = "/test"
	data.RemoteAddress = &ip
	ctx := request.SetContext(context.Background(), data)

	_ = exec.Examine(ctx, "os/exec.Cmd.Run", []string{"sh", "-c", "ls ."}, nil)

	select {
	case <-mockClient.AttackDetectedEventSent:
		assert.Equal(t, "os/exec", mockClient.GetCapturedAttack().Module)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for attack event")
	}
}

func TestExamine_DetectsInjectionThroughEnvironment(t *testing.T) {
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
	data := zenhttp.ContextDataFromRequest(req)
	data.Source = "test"
	data.Route = "/test"
	data.RemoteAddress = &ip
	ctx := request.SetContext(context.Background(), data)

	// Test that injection through environment variables is detected
	// This simulates: cmd := exec.Command("sh", "-c", "$PAYLOAD")
	//                 cmd.Env = []string{"PAYLOAD=ls ."}
	env := []string{"PAYLOAD=ls ."}
	err := exec.Examine(ctx, "os/exec.Cmd.Run", []string{"sh", "-c", "$PAYLOAD"}, env)

	require.Error(t, err, "Should detect injection through environment variable")

	select {
	case <-mockClient.AttackDetectedEventSent:
		assert.Equal(t, "os/exec", mockClient.GetCapturedAttack().Module)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for attack event")
	}
}

func TestExamine_DetectsComplexInjectionThroughEnvironment(t *testing.T) {
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

	req := httptest.NewRequest("GET", "/test?cmd=ls%20.%3B%20cat%20/etc/passwd", nil)
	ip := "127.0.0.1"
	data := zenhttp.ContextDataFromRequest(req)
	data.Source = "test"
	data.Route = "/test"
	data.RemoteAddress = &ip
	ctx := request.SetContext(context.Background(), data)

	// Test that complex injection through environment variables is detected
	// This simulates: cmd := exec.Command("sh", "-c", "$PAYLOAD")
	//                 cmd.Env = []string{"PAYLOAD=ls .; cat /etc/passwd"}
	env := []string{"PAYLOAD=ls .; cat /etc/passwd"}
	err := exec.Examine(ctx, "os/exec.Cmd.Run", []string{"sh", "-c", "$PAYLOAD"}, env)

	require.Error(t, err, "Should detect complex injection through environment variable")

	select {
	case <-mockClient.AttackDetectedEventSent:
		assert.Equal(t, "os/exec", mockClient.GetCapturedAttack().Module)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for attack event")
	}
}

func TestExamine_HandlesMultipleEnvironmentVariables(t *testing.T) {
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

	req := httptest.NewRequest("GET", "/test?file=/etc/passwd", nil)
	ip := "127.0.0.1"
	data := zenhttp.ContextDataFromRequest(req)
	data.Source = "test"
	data.Route = "/test"
	data.RemoteAddress = &ip
	ctx := request.SetContext(context.Background(), data)

	// Test with multiple environment variables
	// This simulates: cmd := exec.Command("sh", "-c", "$CMD $FILE")
	//                 cmd.Env = []string{"CMD=cat", "FILE=/etc/passwd"}
	env := []string{"CMD=cat", "FILE=/etc/passwd"}
	err := exec.Examine(ctx, "os/exec.Cmd.Run", []string{"sh", "-c", "$CMD $FILE"}, env)

	require.Error(t, err, "Should detect injection with multiple environment variables")

	select {
	case <-mockClient.AttackDetectedEventSent:
		assert.Equal(t, "os/exec", mockClient.GetCapturedAttack().Module)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for attack event")
	}
}

func TestExamine_HandlesBracedVariables(t *testing.T) {
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
	data := zenhttp.ContextDataFromRequest(req)
	data.Source = "test"
	data.Route = "/test"
	data.RemoteAddress = &ip
	ctx := request.SetContext(context.Background(), data)

	// Test with braced variable syntax ${VAR}
	// This simulates: cmd := exec.Command("sh", "-c", "${PAYLOAD}")
	//                 cmd.Env = []string{"PAYLOAD=ls ."}
	env := []string{"PAYLOAD=ls ."}
	err := exec.Examine(ctx, "os/exec.Cmd.Run", []string{"sh", "-c", "${PAYLOAD}"}, env)

	require.Error(t, err, "Should detect injection with braced variable syntax")

	select {
	case <-mockClient.AttackDetectedEventSent:
		assert.Equal(t, "os/exec", mockClient.GetCapturedAttack().Module)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for attack event")
	}
}

func TestExpandEnvInCommand(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		env      []string
		expected string
	}{
		{
			name:     "simple variable expansion",
			command:  "$PAYLOAD",
			env:      []string{"PAYLOAD=ls ."},
			expected: "ls .",
		},
		{
			name:     "braced variable expansion",
			command:  "${PAYLOAD}",
			env:      []string{"PAYLOAD=cat /etc/passwd"},
			expected: "cat /etc/passwd",
		},
		{
			name:     "multiple variables",
			command:  "$CMD $FILE",
			env:      []string{"CMD=cat", "FILE=/etc/passwd"},
			expected: "cat /etc/passwd",
		},
		{
			name:     "mixed braced and unbraced",
			command:  "${CMD} $FILE",
			env:      []string{"CMD=cat", "FILE=/etc/passwd"},
			expected: "cat /etc/passwd",
		},
		{
			name:     "variable in middle of string",
			command:  "echo $VAR world",
			env:      []string{"VAR=hello"},
			expected: "echo hello world",
		},
		{
			name:     "no variables",
			command:  "ls .",
			env:      []string{"UNUSED=value"},
			expected: "ls .",
		},
		{
			name:     "undefined variable",
			command:  "$UNDEFINED",
			env:      []string{"OTHER=value"},
			expected: "",
		},
		{
			name:     "empty env",
			command:  "ls .",
			env:      nil,
			expected: "ls .",
		},
		{
			name:     "complex command with injection",
			command:  "$PAYLOAD",
			env:      []string{"PAYLOAD=ls .; cat /etc/passwd"},
			expected: "ls .; cat /etc/passwd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := exec.ExpandEnvInCommand(tt.command, tt.env)
			assert.Equal(t, tt.expected, result)
		})
	}
}


