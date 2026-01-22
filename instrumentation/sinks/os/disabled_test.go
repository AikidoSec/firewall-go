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

func TestExamine_Disabled(t *testing.T) {
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

	err := os.Examine(maliciousPath)

	require.NoError(t, err, "Examine should return early with no error when zen is disabled")

	select {
	case <-mockClient.AttackDetectedEventSent:
		t.Fatal("No attack should be detected when zen is disabled")
	case <-time.After(50 * time.Millisecond):
		// Expected: no attack detected
	}
}
