//go:build !integration

package path_test

import (
	"testing"

	"github.com/AikidoSec/firewall-go/instrumentation/sinks/path"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestExamine_TracksOperationStats(t *testing.T) {
	originalDisabled := config.IsZenDisabled()
	defer config.SetZenDisabled(originalDisabled)

	originalClient := agent.GetCloudClient()
	defer agent.SetCloudClient(originalClient)

	mockClient := testutil.NewMockCloudClient()
	agent.SetCloudClient(mockClient)

	// Clear stats before test
	agent.Stats().GetAndClear()

	// Join multiple paths
	_ = path.Examine([]string{"tmp", "file1.txt"})
	_ = path.Examine([]string{"var", "log", "test.log"})
	_ = path.Examine([]string{"home", "user", "data"})

	// Get stats and verify operations were tracked
	stats := agent.Stats().GetAndClear()
	require.Contains(t, stats.Operations, "path.Join")
	require.Equal(t, 3, stats.Operations["path.Join"].Total, "should track 3 path.Join operations")
}
