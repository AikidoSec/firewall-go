//go:build !integration

package os_test

import (
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/instrumentation/sinks/os"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/testutil"
	"github.com/stretchr/testify/require"
)

func setupDisabledTest(t *testing.T) *testutil.MockCloudClient {
	t.Helper()

	originalDisabled := config.IsZenDisabled()
	originalClient := agent.GetCloudClient()
	originalBlocking := config.IsBlockingEnabled()

	config.SetBlocking(true)
	config.SetZenDisabled(true)

	mockClient := testutil.NewMockCloudClient()
	agent.SetCloudClient(mockClient)

	t.Cleanup(func() {
		config.SetZenDisabled(originalDisabled)
		config.SetBlocking(originalBlocking)
		agent.SetCloudClient(originalClient)
	})

	return mockClient
}

func TestExamineOp_Disabled(t *testing.T) {
	mockClient := setupDisabledTest(t)

	err := os.ExamineOp("os.Chmod", "../../etc/passwd")

	require.NoError(t, err, "ExamineOp should return early with no error when zen is disabled")

	select {
	case <-mockClient.AttackDetectedEventSent:
		t.Fatal("No attack should be detected when zen is disabled")
	case <-time.After(50 * time.Millisecond):
	}
}
