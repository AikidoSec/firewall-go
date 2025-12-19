package internal

import (
	"context"
	"testing"

	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/require"
)

func TestExamineCommand_Disabled(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	zen.SetDisabled(true)

	require.True(t, zen.IsDisabled())

	ctx := context.Background()
	maliciousArgs := []string{"sh", "-c", "echo hello; rm -rf /"}

	err := examineCommand(ctx, "os/exec.Command", maliciousArgs)

	require.NoError(t, err, "Should not detect shell injection when zen is disabled")
}
