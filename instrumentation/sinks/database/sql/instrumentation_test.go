//go:build integration

package sql_test

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestWithBlocking(t *testing.T) (*mockCloudClient, context.Context, *sql.DB, func()) {
	t.Helper()
	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()
	original := config.IsBlockingEnabled()
	config.SetBlocking(true)

	client := &mockCloudClient{
		attackDetectedEventSent: make(chan struct{}, 10),
	}
	agent.SetCloudClient(client)

	req := httptest.NewRequest("GET", "/route?query=1%27%20OR%201%3D1", http.NoBody)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/route",
		RemoteAddress: &ip,
	})

	db, err := sql.Open("test", "")
	require.NoError(t, err)

	cleanup := func() {
		config.SetBlocking(original)
		agent.SetCloudClient(originalClient)
	}

	return client, ctx, db, cleanup
}

func setupTestWithoutBlocking(t *testing.T) (*mockCloudClient, context.Context, *sql.DB, func()) {
	t.Helper()
	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()
	original := config.IsBlockingEnabled()
	config.SetBlocking(false)

	client := &mockCloudClient{
		attackDetectedEventSent: make(chan struct{}, 10),
	}
	agent.SetCloudClient(client)

	req := httptest.NewRequest("GET", "/route?query=1%27%20OR%201%3D1", http.NoBody)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/route",
		RemoteAddress: &ip,
	})

	db, err := sql.Open("test", "")
	require.NoError(t, err)

	cleanup := func() {
		config.SetBlocking(original)
		agent.SetCloudClient(originalClient)
	}

	return client, ctx, db, cleanup
}

func assertAttackBlocked(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)

	var detectedErr *vulnerabilities.AttackDetectedError
	require.ErrorAs(t, err, &detectedErr)

	var attackBlockedErr *zen.AttackBlockedError
	require.ErrorAs(t, err, &attackBlockedErr)
	require.Equal(t, zen.KindSQLInjection, attackBlockedErr.Kind)
}

func waitForAttackEvent(t *testing.T, client *mockCloudClient) {
	t.Helper()

	// Wait for event
	select {
	case <-client.attackDetectedEventSent:
		// Success - verify basic attack details
		assert.Equal(t, "sql_injection", client.capturedAttack.Kind)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for attack event")
	}
}

func waitForAttackEventAndVerifyOnlyOnce(t *testing.T, client *mockCloudClient) {
	t.Helper()

	// Wait for first event
	select {
	case <-client.attackDetectedEventSent:
		// Success - verify basic attack details
		assert.Equal(t, "sql_injection", client.capturedAttack.Kind)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for attack event")
	}

	// Verify no duplicate event arrives
	select {
	case <-client.attackDetectedEventSent:
		t.Fatal("attack was reported more than once")
	case <-time.After(100 * time.Millisecond):
		// Success! No duplicate
	}
}

type dbTestCase struct {
	name      string
	operation string
	testFunc  func(t *testing.T, ctx context.Context, db *sql.DB)
}

func TestDBMethodsReturnErrors(t *testing.T) {
	testCases := []dbTestCase{
		{
			name:      "Query",
			operation: "db.Query",
			testFunc: func(t *testing.T, ctx context.Context, db *sql.DB) {
				t.Helper()
				result, err := db.Query("SELECT * FROM users WHERE id = '1' OR 1=1")
				require.Nil(t, result)
				assertAttackBlocked(t, err)
			},
		},
		{
			name:      "QueryContext",
			operation: "db.QueryContext",
			testFunc: func(t *testing.T, ctx context.Context, db *sql.DB) {
				t.Helper()
				result, err := db.QueryContext(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
				require.Nil(t, result)
				assertAttackBlocked(t, err)
			},
		},
		{
			name:      "QueryRow",
			operation: "db.QueryRow",
			testFunc: func(t *testing.T, ctx context.Context, db *sql.DB) {
				t.Helper()
				row := db.QueryRow("SELECT * FROM users WHERE id = '1' OR 1=1")
				require.NotNil(t, row)
				var id int
				err := row.Scan(&id)
				assertAttackBlocked(t, err)
			},
		},
		{
			name:      "QueryRowContext",
			operation: "db.QueryRowContext",
			testFunc: func(t *testing.T, ctx context.Context, db *sql.DB) {
				t.Helper()
				row := db.QueryRowContext(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
				require.NotNil(t, row)
				var id int
				err := row.Scan(&id)
				assertAttackBlocked(t, err)
			},
		},
		{
			name:      "Exec",
			operation: "db.Exec",
			testFunc: func(t *testing.T, ctx context.Context, db *sql.DB) {
				t.Helper()
				result, err := db.Exec("DELETE FROM users WHERE id = '1' OR 1=1")
				require.Nil(t, result)
				assertAttackBlocked(t, err)
			},
		},
		{
			name:      "ExecContext",
			operation: "db.ExecContext",
			testFunc: func(t *testing.T, ctx context.Context, db *sql.DB) {
				t.Helper()
				result, err := db.ExecContext(ctx, "DELETE FROM users WHERE id = '1' OR 1=1")
				require.Nil(t, result)
				assertAttackBlocked(t, err)
			},
		},
		{
			name:      "Prepare",
			operation: "db.Prepare",
			testFunc: func(t *testing.T, ctx context.Context, db *sql.DB) {
				t.Helper()
				stmt, err := db.Prepare("SELECT * FROM users WHERE id = '1' OR 1=1")
				require.Nil(t, stmt)
				assertAttackBlocked(t, err)
			},
		},
		{
			name:      "PrepareContext",
			operation: "db.PrepareContext",
			testFunc: func(t *testing.T, ctx context.Context, db *sql.DB) {
				t.Helper()
				stmt, err := db.PrepareContext(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
				require.Nil(t, stmt)
				assertAttackBlocked(t, err)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client, ctx, db, cleanup := setupTestWithBlocking(t)
			defer cleanup()

			request.WrapWithGLS(ctx, func() {
				tc.testFunc(t, ctx, db)
			})

			waitForAttackEvent(t, client)
		})
	}
}

func TestDBMethodsReportOnlyOnce(t *testing.T) {
	testCases := []dbTestCase{
		{
			name:      "Query",
			operation: "db.Query",
			testFunc: func(t *testing.T, ctx context.Context, db *sql.DB) {
				t.Helper()
				_, _ = db.Query("SELECT * FROM users WHERE id = '1' OR 1=1")
			},
		},
		{
			name:      "QueryContext",
			operation: "db.QueryContext",
			testFunc: func(t *testing.T, ctx context.Context, db *sql.DB) {
				t.Helper()
				_, _ = db.QueryContext(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
			},
		},
		{
			name:      "QueryRow",
			operation: "db.QueryRow",
			testFunc: func(t *testing.T, ctx context.Context, db *sql.DB) {
				t.Helper()
				row := db.QueryRow("SELECT * FROM users WHERE id = '1' OR 1=1")
				var id int
				_ = row.Scan(&id)
			},
		},
		{
			name:      "QueryRowContext",
			operation: "db.QueryRowContext",
			testFunc: func(t *testing.T, ctx context.Context, db *sql.DB) {
				t.Helper()
				row := db.QueryRowContext(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
				var id int
				_ = row.Scan(&id)
			},
		},
		{
			name:      "Exec",
			operation: "db.Exec",
			testFunc: func(t *testing.T, ctx context.Context, db *sql.DB) {
				t.Helper()
				_, _ = db.Exec("DELETE FROM users WHERE id = '1' OR 1=1")
			},
		},
		{
			name:      "ExecContext",
			operation: "db.ExecContext",
			testFunc: func(t *testing.T, ctx context.Context, db *sql.DB) {
				t.Helper()
				_, _ = db.ExecContext(ctx, "DELETE FROM users WHERE id = '1' OR 1=1")
			},
		},
		{
			name:      "Prepare",
			operation: "db.Prepare",
			testFunc: func(t *testing.T, ctx context.Context, db *sql.DB) {
				t.Helper()
				_, _ = db.Prepare("SELECT * FROM users WHERE id = '1' OR 1=1")
			},
		},
		{
			name:      "PrepareContext",
			operation: "db.PrepareContext",
			testFunc: func(t *testing.T, ctx context.Context, db *sql.DB) {
				t.Helper()
				_, _ = db.PrepareContext(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client, ctx, db, cleanup := setupTestWithoutBlocking(t)
			defer cleanup()

			request.WrapWithGLS(ctx, func() {
				tc.testFunc(t, ctx, db)
			})

			waitForAttackEventAndVerifyOnlyOnce(t, client)
		})
	}
}

type txTestCase struct {
	name      string
	operation string
	testFunc  func(t *testing.T, ctx context.Context, tx *sql.Tx)
}

func TestTxMethodsReturnErrors(t *testing.T) {
	testCases := []txTestCase{
		{
			name:      "Query",
			operation: "tx.Query",
			testFunc: func(t *testing.T, ctx context.Context, tx *sql.Tx) {
				t.Helper()
				result, err := tx.Query("SELECT * FROM users WHERE id = '1' OR 1=1")
				require.Nil(t, result)
				assertAttackBlocked(t, err)
			},
		},
		{
			name:      "QueryContext",
			operation: "tx.QueryContext",
			testFunc: func(t *testing.T, ctx context.Context, tx *sql.Tx) {
				t.Helper()
				result, err := tx.QueryContext(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
				require.Nil(t, result)
				assertAttackBlocked(t, err)
			},
		},
		{
			name:      "QueryRow",
			operation: "tx.QueryRow",
			testFunc: func(t *testing.T, ctx context.Context, tx *sql.Tx) {
				t.Helper()
				row := tx.QueryRow("SELECT * FROM users WHERE id = '1' OR 1=1")
				require.NotNil(t, row)
				var id int
				err := row.Scan(&id)
				assertAttackBlocked(t, err)
			},
		},
		{
			name:      "QueryRowContext",
			operation: "tx.QueryRowContext",
			testFunc: func(t *testing.T, ctx context.Context, tx *sql.Tx) {
				t.Helper()
				row := tx.QueryRowContext(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
				require.NotNil(t, row)
				var id int
				err := row.Scan(&id)
				assertAttackBlocked(t, err)
			},
		},
		{
			name:      "Exec",
			operation: "tx.Exec",
			testFunc: func(t *testing.T, ctx context.Context, tx *sql.Tx) {
				t.Helper()
				result, err := tx.Exec("DELETE FROM users WHERE id = '1' OR 1=1")
				require.Nil(t, result)
				assertAttackBlocked(t, err)
			},
		},
		{
			name:      "ExecContext",
			operation: "tx.ExecContext",
			testFunc: func(t *testing.T, ctx context.Context, tx *sql.Tx) {
				t.Helper()
				result, err := tx.ExecContext(ctx, "DELETE FROM users WHERE id = '1' OR 1=1")
				require.Nil(t, result)
				assertAttackBlocked(t, err)
			},
		},
		{
			name:      "Prepare",
			operation: "tx.Prepare",
			testFunc: func(t *testing.T, ctx context.Context, tx *sql.Tx) {
				t.Helper()
				stmt, err := tx.Prepare("SELECT * FROM users WHERE id = '1' OR 1=1")
				require.Nil(t, stmt)
				assertAttackBlocked(t, err)
			},
		},
		{
			name:      "PrepareContext",
			operation: "tx.PrepareContext",
			testFunc: func(t *testing.T, ctx context.Context, tx *sql.Tx) {
				t.Helper()
				stmt, err := tx.PrepareContext(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
				require.Nil(t, stmt)
				assertAttackBlocked(t, err)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client, ctx, db, cleanup := setupTestWithBlocking(t)
			defer cleanup()

			tx, err := db.Begin()
			require.NoError(t, err)
			defer tx.Rollback()

			request.WrapWithGLS(ctx, func() {
				tc.testFunc(t, ctx, tx)
			})

			waitForAttackEvent(t, client)
		})
	}
}

func TestTxMethodsReportOnlyOnce(t *testing.T) {
	testCases := []txTestCase{
		{
			name:      "Query",
			operation: "tx.Query",
			testFunc: func(t *testing.T, ctx context.Context, tx *sql.Tx) {
				t.Helper()
				_, _ = tx.Query("SELECT * FROM users WHERE id = '1' OR 1=1")
			},
		},
		{
			name:      "QueryContext",
			operation: "tx.QueryContext",
			testFunc: func(t *testing.T, ctx context.Context, tx *sql.Tx) {
				t.Helper()
				_, _ = tx.QueryContext(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
			},
		},
		{
			name:      "QueryRow",
			operation: "tx.QueryRow",
			testFunc: func(t *testing.T, ctx context.Context, tx *sql.Tx) {
				t.Helper()
				row := tx.QueryRow("SELECT * FROM users WHERE id = '1' OR 1=1")
				var id int
				_ = row.Scan(&id)
			},
		},
		{
			name:      "QueryRowContext",
			operation: "tx.QueryRowContext",
			testFunc: func(t *testing.T, ctx context.Context, tx *sql.Tx) {
				t.Helper()
				row := tx.QueryRowContext(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
				var id int
				_ = row.Scan(&id)
			},
		},
		{
			name:      "Exec",
			operation: "tx.Exec",
			testFunc: func(t *testing.T, ctx context.Context, tx *sql.Tx) {
				t.Helper()
				_, _ = tx.Exec("DELETE FROM users WHERE id = '1' OR 1=1")
			},
		},
		{
			name:      "ExecContext",
			operation: "tx.ExecContext",
			testFunc: func(t *testing.T, ctx context.Context, tx *sql.Tx) {
				t.Helper()
				_, _ = tx.ExecContext(ctx, "DELETE FROM users WHERE id = '1' OR 1=1")
			},
		},
		{
			name:      "Prepare",
			operation: "tx.Prepare",
			testFunc: func(t *testing.T, ctx context.Context, tx *sql.Tx) {
				t.Helper()
				_, _ = tx.Prepare("SELECT * FROM users WHERE id = '1' OR 1=1")
			},
		},
		{
			name:      "PrepareContext",
			operation: "tx.PrepareContext",
			testFunc: func(t *testing.T, ctx context.Context, tx *sql.Tx) {
				t.Helper()
				_, _ = tx.PrepareContext(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client, ctx, db, cleanup := setupTestWithoutBlocking(t)
			defer cleanup()

			tx, err := db.Begin()
			require.NoError(t, err)
			defer tx.Rollback()

			request.WrapWithGLS(ctx, func() {
				tc.testFunc(t, ctx, tx)
			})

			waitForAttackEventAndVerifyOnlyOnce(t, client)
		})
	}
}

func TestQueryContextIsAutomaticallyInstrumented(t *testing.T) {
	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()

	// Enable blocking so that Zen should cause QueryContext to return an error
	original := config.IsBlockingEnabled()
	config.SetBlocking(true)

	t.Cleanup(func() {
		config.SetBlocking(original)
		agent.SetCloudClient(originalClient)
	})

	client := &mockCloudClient{
		attackDetectedEventSent: make(chan struct{}),
	}
	agent.SetCloudClient(client)

	req := httptest.NewRequest("GET", "/route?query=1%27%20OR%201%3D1", http.NoBody)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/route",
		RemoteAddress: &ip,
	})

	db, err := sql.Open("test", "")
	require.NoError(t, err)

	request.WrapWithGLS(ctx, func() {
		result, err := db.QueryContext(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
		require.Nil(t, result)
		require.Error(t, err)

		var detectedErr *vulnerabilities.AttackDetectedError
		require.ErrorAs(t, err, &detectedErr)

		var attackBlockedErr *zen.AttackBlockedError
		require.ErrorAs(t, err, &attackBlockedErr)
		require.Equal(t, zen.KindSQLInjection, attackBlockedErr.Kind)
	})

	select {
	case <-client.attackDetectedEventSent:
		// Success
		assert.Equal(t, "GET", client.capturedRequest.Method)
		assert.Equal(t, "127.0.0.1", client.capturedRequest.IPAddress)
		assert.Equal(t, "unknown", client.capturedRequest.UserAgent)
		assert.Equal(t, "http://example.com/route?query=1%27%20OR%201%3D1", client.capturedRequest.URL)
		assert.Equal(t, "test", client.capturedRequest.Source)
		assert.Equal(t, "/route", client.capturedRequest.Route)

		assert.Equal(t, "sql_injection", client.capturedAttack.Kind)
		assert.True(t, client.capturedAttack.Blocked)
		assert.Equal(t, "database/sql.DB.Query(Row)Context", client.capturedAttack.Operation)
		assert.Equal(t, "Module", client.capturedAttack.Module)
		assert.Equal(t, ".query", client.capturedAttack.Path)
		assert.Equal(t, "1' OR 1=1", client.capturedAttack.Payload)
		assert.Equal(t, map[string]string{
			"dialect": "default",
			"sql":     "SELECT * FROM users WHERE id = '1' OR 1=1",
		}, client.capturedAttack.Metadata)
		assert.Nil(t, nil, client.capturedAttack.User)

		assert.NotEmpty(t, client.capturedAgentInfo)

	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for attack event")
	}
}

type mockCloudClient struct {
	attackDetectedEventSent chan struct{}
	capturedAgentInfo       cloud.AgentInfo
	capturedRequest         aikido_types.RequestInfo
	capturedAttack          aikido_types.AttackDetails
	mu                      sync.Mutex
}

func (m *mockCloudClient) SendStartEvent(agentInfo cloud.AgentInfo) (*aikido_types.CloudConfigData, error) {
	panic("not implemented")
}

func (m *mockCloudClient) SendHeartbeatEvent(agentInfo cloud.AgentInfo, data cloud.HeartbeatData) (*aikido_types.CloudConfigData, error) {
	panic("not implemented")
}

func (m *mockCloudClient) FetchConfigUpdatedAt() time.Time { panic("not implemented") }
func (m *mockCloudClient) FetchConfig() (*aikido_types.CloudConfigData, error) {
	panic("not implemented")
}

func (m *mockCloudClient) FetchListsConfig() (*aikido_types.ListsConfigData, error) {
	panic("not implemented")
}

func (m *mockCloudClient) SendAttackDetectedEvent(agentInfo cloud.AgentInfo, request aikido_types.RequestInfo, attack aikido_types.AttackDetails) {
	m.mu.Lock()
	m.capturedAgentInfo = agentInfo
	m.capturedRequest = request
	m.capturedAttack = attack
	m.mu.Unlock()

	m.attackDetectedEventSent <- struct{}{}
}

func (m *mockCloudClient) SendAttackWaveDetectedEvent(agentInfo cloud.AgentInfo, request cloud.AttackWaveRequestInfo, attack cloud.AttackWaveDetails) {
	panic("not implemented")
}
