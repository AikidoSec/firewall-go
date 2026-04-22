//go:build !integration

package os_test

import (
	"testing"

	"github.com/AikidoSec/firewall-go/instrumentation/sinks/os"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/testutil"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/require"
)

func TestExamineOp_TracksOperationStats(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()
	defer agent.SetCloudClient(originalClient)

	mockClient := testutil.NewMockCloudClient()
	agent.SetCloudClient(mockClient)

	agent.Stats().GetAndClear()

	_ = os.ExamineOp("os.OpenFile", "/tmp/file1.txt")
	_ = os.ExamineOp("os.OpenFile", "/tmp/file2.txt")
	_ = os.ExamineOp("os.Chmod", "/tmp/test.txt")

	stats := agent.Stats().GetAndClear()
	require.Equal(t, 2, stats.Operations["os.OpenFile"].Total)
	require.Equal(t, 1, stats.Operations["os.Chmod"].Total)
}
