//go:build integration

package pgx_test

import (
	"context"
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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestWithBlocking(t *testing.T) (*mockCloudClient, context.Context, *pgxpool.Pool, func()) {
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

	// Create a pool config with test database connection string
	// The database is automatically started by 'make test-instrumentation-integration'
	poolConfig, err := pgxpool.ParseConfig("postgres://testuser:testpass@localhost:5433/testdb?sslmode=disable")
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v\nRun tests with: make test-instrumentation-integration", err)
	}

	cleanup := func() {
		if pool != nil {
			pool.Close()
		}
		config.SetBlocking(original)
		agent.SetCloudClient(originalClient)
	}

	return client, ctx, pool, cleanup
}

func setupTestWithoutBlocking(t *testing.T) (*mockCloudClient, context.Context, *pgxpool.Pool, func()) {
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

	// Create a pool config with test database connection string
	// The database is automatically started by 'make test-instrumentation-integration'
	poolConfig, err := pgxpool.ParseConfig("postgres://testuser:testpass@localhost:5433/testdb?sslmode=disable")
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v\nRun tests with: make test-instrumentation-integration", err)
	}

	cleanup := func() {
		if pool != nil {
			pool.Close()
		}
		config.SetBlocking(original)
		agent.SetCloudClient(originalClient)
	}

	return client, ctx, pool, cleanup
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

type poolTestCase struct {
	name      string
	operation string
	testFunc  func(t *testing.T, ctx context.Context, pool *pgxpool.Pool)
}

func TestPoolMethodsReturnErrors(t *testing.T) {
	testCases := []poolTestCase{
		{
			name:      "Query",
			operation: "pool.Query",
			testFunc: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				rows, err := pool.Query(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
				require.NotNil(t, rows)
				assertAttackBlocked(t, err)
				assertAttackBlocked(t, rows.Err())
			},
		},
		{
			name:      "QueryRow",
			operation: "pool.QueryRow",
			testFunc: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				row := pool.QueryRow(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
				require.NotNil(t, row)
				var id int
				err := row.Scan(&id)
				assertAttackBlocked(t, err)
			},
		},
		{
			name:      "Exec",
			operation: "pool.Exec",
			testFunc: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				tag, err := pool.Exec(ctx, "DELETE FROM users WHERE id = '1' OR 1=1")
				require.Equal(t, pgconn.CommandTag{}, tag)
				assertAttackBlocked(t, err)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client, ctx, pool, cleanup := setupTestWithBlocking(t)
			defer cleanup()

			request.WrapWithGLS(ctx, func() {
				tc.testFunc(t, ctx, pool)
			})

			waitForAttackEvent(t, client)
		})
	}
}

func TestPoolMethodsReportOnlyOnce(t *testing.T) {
	testCases := []poolTestCase{
		{
			name:      "Query",
			operation: "pool.Query",
			testFunc: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				rows, err := pool.Query(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
				_ = rows
				_ = err
			},
		},
		{
			name:      "QueryRow",
			operation: "pool.QueryRow",
			testFunc: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				row := pool.QueryRow(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
				var id int
				_ = row.Scan(&id)
			},
		},
		{
			name:      "Exec",
			operation: "pool.Exec",
			testFunc: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
				_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = '1' OR 1=1")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client, ctx, pool, cleanup := setupTestWithoutBlocking(t)
			defer cleanup()

			request.WrapWithGLS(ctx, func() {
				tc.testFunc(t, ctx, pool)
			})

			waitForAttackEventAndVerifyOnlyOnce(t, client)
		})
	}
}

type txTestCase struct {
	name      string
	operation string
	testFunc  func(t *testing.T, ctx context.Context, tx pgx.Tx)
}

func TestTxMethodsReturnErrors(t *testing.T) {
	testCases := []txTestCase{
		{
			name:      "Query",
			operation: "tx.Query",
			testFunc: func(t *testing.T, ctx context.Context, tx pgx.Tx) {
				rows, err := tx.Query(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
				require.NotNil(t, rows)
				assertAttackBlocked(t, err)
				assertAttackBlocked(t, rows.Err())
			},
		},
		{
			name:      "QueryRow",
			operation: "tx.QueryRow",
			testFunc: func(t *testing.T, ctx context.Context, tx pgx.Tx) {
				row := tx.QueryRow(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
				require.NotNil(t, row)
				var id int
				err := row.Scan(&id)
				assertAttackBlocked(t, err)
			},
		},
		{
			name:      "Exec",
			operation: "tx.Exec",
			testFunc: func(t *testing.T, ctx context.Context, tx pgx.Tx) {
				tag, err := tx.Exec(ctx, "DELETE FROM users WHERE id = '1' OR 1=1")
				require.Equal(t, pgconn.CommandTag{}, tag)
				assertAttackBlocked(t, err)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client, ctx, pool, cleanup := setupTestWithBlocking(t)
			defer cleanup()

			request.WrapWithGLS(ctx, func() {
				// Acquire a connection and begin a transaction
				conn, err := pool.Acquire(ctx)
				require.NoError(t, err, "Failed to acquire connection")
				defer conn.Release()

				tx, err := conn.Begin(ctx)
				require.NoError(t, err, "Failed to begin transaction")
				defer tx.Rollback(ctx)

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
			testFunc: func(t *testing.T, ctx context.Context, tx pgx.Tx) {
				rows, err := tx.Query(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
				_ = rows
				_ = err
			},
		},
		{
			name:      "QueryRow",
			operation: "tx.QueryRow",
			testFunc: func(t *testing.T, ctx context.Context, tx pgx.Tx) {
				row := tx.QueryRow(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
				var id int
				_ = row.Scan(&id)
			},
		},
		{
			name:      "Exec",
			operation: "tx.Exec",
			testFunc: func(t *testing.T, ctx context.Context, tx pgx.Tx) {
				_, _ = tx.Exec(ctx, "DELETE FROM users WHERE id = '1' OR 1=1")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client, ctx, pool, cleanup := setupTestWithoutBlocking(t)
			defer cleanup()

			request.WrapWithGLS(ctx, func() {
				conn, err := pool.Acquire(ctx)
				require.NoError(t, err, "Failed to acquire connection")
				defer conn.Release()

				tx, err := conn.Begin(ctx)
				require.NoError(t, err, "Failed to begin transaction")
				defer tx.Rollback(ctx)

				tc.testFunc(t, ctx, tx)
			})

			waitForAttackEventAndVerifyOnlyOnce(t, client)
		})
	}
}

func TestBatchQueryReturnsError(t *testing.T) {
	client, ctx, pool, cleanup := setupTestWithBlocking(t)
	defer cleanup()

	request.WrapWithGLS(ctx, func() {
		batch := &pgx.Batch{}

		batch.Queue("INSERT INTO users (id) VALUES ($1)", 321).Exec(func(tag pgconn.CommandTag) error {
			t.Fatal("this should not be called")
			return nil
		})
		batch.Queue("SELECT name FROM users where id = $1", 123).QueryRow(func(row pgx.Row) error {
			t.Fatal("this should not be called")
			return nil
		})
		batch.Queue("SELECT name from users where id = '1' OR 1=1").QueryRow(func(row pgx.Row) error {
			t.Fatal("this should not be called")
			return nil
		})

		result := pool.SendBatch(ctx, batch)
		_, err := result.Query()
		assertAttackBlocked(t, err)

		result.Close()
	})

	waitForAttackEvent(t, client)
}

func TestQueryIsAutomaticallyInstrumented(t *testing.T) {
	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()

	// Enable blocking so that Zen should cause Query to return an error
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

	// Create a pool config with test database connection string
	// The database is automatically started by 'make test-instrumentation-integration'
	poolConfig, err := pgxpool.ParseConfig("postgres://testuser:testpass@localhost:5433/testdb?sslmode=disable")
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v\nRun tests with: make test-instrumentation-integration", err)
	}
	defer pool.Close()

	request.WrapWithGLS(ctx, func() {
		rows, err := pool.Query(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
		require.NotNil(t, rows)
		require.Error(t, err)
		assertAttackBlocked(t, rows.Err())

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
		assert.Equal(t, "pgx.Conn.Query", client.capturedAttack.Operation)
		assert.Equal(t, "Module", client.capturedAttack.Module)
		assert.Equal(t, ".query", client.capturedAttack.Path)
		assert.Equal(t, "1' OR 1=1", client.capturedAttack.Payload)
		assert.Equal(t, map[string]string{
			"dialect": "postgres",
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
