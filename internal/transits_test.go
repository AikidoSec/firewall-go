package internal

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestExamineCommand_Disabled(t *testing.T) {
	originalDisabled := config.IsZenDisabled()
	defer config.SetZenDisabled(originalDisabled)

	originalClient := agent.GetCloudClient()
	originalBlocking := config.IsBlockingEnabled()
	config.SetBlocking(true)
	defer func() {
		config.SetBlocking(originalBlocking)
		agent.SetCloudClient(originalClient)
	}()

	mockClient := testutil.NewMockCloudClient()
	agent.SetCloudClient(mockClient)

	req := httptest.NewRequest("GET", "/test?cmd=rm%20-rf%20%2F", nil)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/test",
		RemoteAddress: &ip,
	})

	config.SetZenDisabled(true)

	maliciousArgs := []string{"sh", "-c", "echo hello; rm -rf /"}

	err := examineCommand(ctx, "os/exec.Command", maliciousArgs)

	require.NoError(t, err, "Should not detect shell injection when zen is disabled")

	select {
	case <-mockClient.AttackDetectedEventSent:
		t.Fatal("No attack should be detected when zen is disabled")
	case <-time.After(50 * time.Millisecond):
		// Expected: no attack detected
	}
}

func TestExaminePath_Disabled(t *testing.T) {
	originalDisabled := config.IsZenDisabled()
	defer config.SetZenDisabled(originalDisabled)

	originalClient := agent.GetCloudClient()
	originalBlocking := config.IsBlockingEnabled()
	config.SetBlocking(true)
	defer func() {
		config.SetBlocking(originalBlocking)
		agent.SetCloudClient(originalClient)
	}()

	mockClient := testutil.NewMockCloudClient()
	agent.SetCloudClient(mockClient)

	config.SetZenDisabled(true)

	maliciousPath := "../../etc/passwd"

	err := examinePath("os.OpenFeil", []string{maliciousPath}, false)

	require.NoError(t, err, "Examine should return early with no error when zen is disabled")

	select {
	case <-mockClient.AttackDetectedEventSent:
		t.Fatal("No attack should be detected when zen is disabled")
	case <-time.After(50 * time.Millisecond):
		// Expected: no attack detected
	}
}
