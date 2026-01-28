//go:build !integration

package os_test

import (
	"testing"

	"github.com/AikidoSec/firewall-go/instrumentation/sinks/os"
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

	// Open multiple files
	_ = os.Examine("/tmp/file1.txt")
	_ = os.Examine("/tmp/file2.txt")
	_ = os.Examine("/var/log/test.log")

	// Get stats and verify operations were tracked
	stats := agent.Stats().GetAndClear()
	require.Contains(t, stats.Operations, "os.OpenFile")
	require.Equal(t, 3, stats.Operations["os.OpenFile"].Total, "should track 3 file operations")
}
