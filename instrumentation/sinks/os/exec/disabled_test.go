//go:build !integration

package exec_test

import (
	"context"
	"testing"

	exec "github.com/AikidoSec/firewall-go/instrumentation/sinks/os/exec"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/require"
)

func TestExamine_Disabled(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	zen.SetDisabled(true)

	require.True(t, zen.IsDisabled())

	ctx := context.Background()
	maliciousArgs := []string{"sh", "-c", "echo hello; rm -rf /"}

	err := exec.Examine(ctx, maliciousArgs, "os/exec.Command")

	require.NoError(t, err, "Should not detect shell injection when zen is disabled")
}

