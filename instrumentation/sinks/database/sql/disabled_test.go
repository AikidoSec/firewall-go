//go:build !integration

package sql_test

import (
	"context"
	"testing"

	sql "github.com/AikidoSec/firewall-go/instrumentation/sinks/database/sql"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/require"
)

func TestExamineContext_Disabled(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	zen.SetDisabled(true)

	require.True(t, zen.IsDisabled())

	ctx := context.Background()
	maliciousQuery := "SELECT * FROM users WHERE id = '1' OR 1=1"

	err := sql.ExamineContext(ctx, maliciousQuery, "database/sql.DB.QueryContext")

	require.NoError(t, err, "Should not detect attacks when zen is disabled")
}
