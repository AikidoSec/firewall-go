//go:build !integration

package filepath_test

import (
	"testing"

	"github.com/AikidoSec/firewall-go/instrumentation/sinks/path/filepath"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/testutil"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/require"
)

func TestExamineDeferred_ReturnsEarlyWhenDisabled(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	zen.SetDisabled(true)
	require.True(t, zen.IsDisabled())

	err := filepath.ExamineDeferred("filepath.Join", []string{"..", "etc", "passwd"})
	require.NoError(t, err)
}

func TestExamine_ReturnsEarlyWhenDisabled(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	zen.SetDisabled(true)
	require.True(t, zen.IsDisabled())

	err := filepath.Examine("filepath.Walk", "/tmp/safe")
	require.NoError(t, err)

	err = filepath.ExamineArg("filepath.Clean", "../etc/passwd")
	require.NoError(t, err)
}

func TestExamineDeferred_TracksJoinOperationStats(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()
	defer agent.SetCloudClient(originalClient)

	mockClient := testutil.NewMockCloudClient()
	agent.SetCloudClient(mockClient)

	agent.Stats().GetAndClear()

	_ = filepath.ExamineDeferred("filepath.Join", []string{"tmp", "file1.txt"})
	_ = filepath.ExamineDeferred("filepath.Join", []string{"var", "log", "test.log"})
	_ = filepath.ExamineDeferred("filepath.Join", []string{"home", "user", "data"})

	stats := agent.Stats().GetAndClear()
	require.Contains(t, stats.Operations, "filepath.Join")
	require.Equal(t, 3, stats.Operations["filepath.Join"].Total, "should track 3 filepath.Join operations")
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

	_ = filepath.Examine("filepath.Walk", "/tmp/a")
	_ = filepath.Examine("filepath.WalkDir", "/tmp/b")
	_ = filepath.Examine("filepath.Glob", "/tmp/*.txt")

	stats := agent.Stats().GetAndClear()
	require.Contains(t, stats.Operations, "filepath.Walk")
	require.Equal(t, 1, stats.Operations["filepath.Walk"].Total)
	require.Contains(t, stats.Operations, "filepath.WalkDir")
	require.Equal(t, 1, stats.Operations["filepath.WalkDir"].Total)
	require.Contains(t, stats.Operations, "filepath.Glob")
	require.Equal(t, 1, stats.Operations["filepath.Glob"].Total)
}

func TestExamineArg_TracksCleanOperationStats(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()
	defer agent.SetCloudClient(originalClient)

	mockClient := testutil.NewMockCloudClient()
	agent.SetCloudClient(mockClient)

	agent.Stats().GetAndClear()

	_ = filepath.ExamineArg("filepath.Clean", "/tmp/file.txt")
	_ = filepath.ExamineArg("filepath.Clean", "/var/log/test.log")

	stats := agent.Stats().GetAndClear()
	require.Contains(t, stats.Operations, "filepath.Clean")
	require.Equal(t, 2, stats.Operations["filepath.Clean"].Total, "should track 2 filepath.Clean operations")
}
