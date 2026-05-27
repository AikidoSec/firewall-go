//go:build !integration

package path_test

import (
	"testing"

	"github.com/AikidoSec/firewall-go/instrumentation/sinks/path"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/testutil"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/require"
)

func TestExamine_ReturnsEarlyWhenDisabled(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	zen.SetDisabled(true)
	require.True(t, zen.IsDisabled())

	err := path.Examine("path.Join", []string{"..", "etc", "passwd"})
	require.NoError(t, err)

	err = path.ExamineArg("path.Clean", "../etc/passwd")
	require.NoError(t, err)
}

func TestExamine_TracksOperationStats(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()
	defer agent.SetCloudClient(originalClient)

	mockClient := testutil.NewMockCloudClient()
	agent.SetCloudClient(mockClient)

	agent.Stats().GetAndClear()

	_ = path.Examine("path.Join", []string{"tmp", "file1.txt"})
	_ = path.Examine("path.Join", []string{"var", "log", "test.log"})
	_ = path.Examine("path.Join", []string{"home", "user", "data"})

	stats := agent.Stats().GetAndClear()
	require.Contains(t, stats.Operations, "path.Join")
	require.Equal(t, 3, stats.Operations["path.Join"].Total, "should track 3 path.Join operations")
}

func TestExamine_TracksCleanOperationStats(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()
	defer agent.SetCloudClient(originalClient)

	mockClient := testutil.NewMockCloudClient()
	agent.SetCloudClient(mockClient)

	agent.Stats().GetAndClear()

	_ = path.Examine("path.Clean", []string{"/tmp/file.txt"})
	_ = path.Examine("path.Clean", []string{"/var/log/test.log"})

	stats := agent.Stats().GetAndClear()
	require.Contains(t, stats.Operations, "path.Clean")
	require.Equal(t, 2, stats.Operations["path.Clean"].Total, "should track 2 path.Clean operations")
}
