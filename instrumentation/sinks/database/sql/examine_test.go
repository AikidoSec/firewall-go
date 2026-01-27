//go:build !integration

package sql_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/AikidoSec/firewall-go/instrumentation/sinks/database/sql"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/internal/testutil"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/require"
)

func TestExamineContext_TracksOperationStats(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()
	defer agent.SetCloudClient(originalClient)

	mockClient := testutil.NewMockCloudClient()
	agent.SetCloudClient(mockClient)

	req := httptest.NewRequest("GET", "/test", nil)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/test",
		RemoteAddress: &ip,
	})

	// Clear stats before test
	agent.Stats().GetAndClear()

	// Execute multiple queries
	query := "SELECT * FROM users WHERE id = 1"
	_ = sql.ExamineContext(ctx, query, "database/sql.DB.Query")
	_ = sql.ExamineContext(ctx, query, "database/sql.DB.Query")
	_ = sql.ExamineContext(ctx, "INSERT INTO users VALUES (1)", "database/sql.DB.Exec")

	// Get stats and verify operations were tracked
	stats := agent.Stats().GetAndClear()
	require.Contains(t, stats.Operations, "database/sql.DB.Query")
	require.Contains(t, stats.Operations, "database/sql.DB.Exec")

	require.Equal(t, 2, stats.Operations["database/sql.DB.Query"].Total, "Query should be called twice")
	require.Equal(t, 1, stats.Operations["database/sql.DB.Exec"].Total, "Exec should be called once")
}
