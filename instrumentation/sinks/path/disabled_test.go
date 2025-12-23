//go:build !integration

package path_test

import (
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/instrumentation/sinks/path"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/testutil"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/require"
)

func TestExamine_Disabled(t *testing.T) {
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

	zen.SetDisabled(true)
	require.True(t, zen.IsDisabled(), "zen should be disabled")

	maliciousArgs := []string{"../../", "etc/", "passwd"}

	path.Examine(maliciousArgs)

	select {
	case <-mockClient.AttackDetectedEventSent:
		t.Fatal("No attack should be detected when zen is disabled")
	case <-time.After(50 * time.Millisecond):
		// Expected: no attack detected
	}
}
