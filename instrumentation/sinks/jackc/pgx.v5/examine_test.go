//go:build !integration

package pgx_test

import (
	"context"
	"net/http/httptest"
	"testing"

	zenhttp "github.com/AikidoSec/firewall-go/instrumentation/http"
	"github.com/AikidoSec/firewall-go/instrumentation/sinks/jackc/pgx.v5"
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
	data := zenhttp.ContextDataFromRequest(req)
	data.Source = "test"
	data.Route = "/test"
	data.RemoteAddress = &ip
	ctx := request.SetContext(context.Background(), data)

	// Clear stats before test
	agent.Stats().GetAndClear()

	// Execute multiple queries
	query := "SELECT * FROM users WHERE id = 1"
	_ = pgx.ExamineContext(ctx, query, "github.com/jackc/pgx/v5.Conn.Query")
	_ = pgx.ExamineContext(ctx, query, "github.com/jackc/pgx/v5.Conn.Query")
	_ = pgx.ExamineContext(ctx, "INSERT INTO users VALUES (1)", "github.com/jackc/pgx/v5.Conn.Exec")

	// Get stats and verify operations were tracked
	stats := agent.Stats().GetAndClear()
	require.Contains(t, stats.Operations, "github.com/jackc/pgx/v5.Conn.Query")
	require.Contains(t, stats.Operations, "github.com/jackc/pgx/v5.Conn.Exec")

	require.Equal(t, 2, stats.Operations["github.com/jackc/pgx/v5.Conn.Query"].Total, "Query should be called twice")
	require.Equal(t, 1, stats.Operations["github.com/jackc/pgx/v5.Conn.Exec"].Total, "Exec should be called once")
}
