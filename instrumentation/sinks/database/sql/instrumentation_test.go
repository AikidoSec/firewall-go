//go:build integration

package sql_test

import (
	"context"
	"database/sql"
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

func TestQueryContextIsAutomaticallyInstrumented(t *testing.T) {
	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()

	// Enable blocking so that Zen should cause QueryContext to panic
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

	req := httptest.NewRequest("GET", "/route?query=1%27%20OR%201%3D1", nil)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, "/route", "test", &ip, nil)

	db, err := sql.Open("test", "")
	require.NoError(t, err)

	request.WrapWithGLS(ctx, func() {
		require.Panics(t, func() {
			_, _ = db.QueryContext(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
		})
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

func TestQueryShouldReportAttackOnlyOnce(t *testing.T) {
	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()

	// Disabling blocking so that we would see attack being detected twice.
	// Through both Query and QueryContext
	original := config.IsBlockingEnabled()
	config.SetBlocking(false)

	t.Cleanup(func() {
		config.SetBlocking(original)
		agent.SetCloudClient(originalClient)
	})

	client := &mockCloudClient{
		attackDetectedEventSent: make(chan struct{}),
	}

	agent.SetCloudClient(client)

	req := httptest.NewRequest("GET", "/route?query=1%27%20OR%201%3D1", nil)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, "/route", "test", &ip, nil)

	db, err := sql.Open("test", "")
	require.NoError(t, err)

	request.WrapWithGLS(ctx, func() {
		require.NotPanics(t, func() {
			_, _ = db.Query("SELECT * FROM users WHERE id = '1' OR 1=1")
		})
	})

	// Wait for first event
	select {
	case <-client.attackDetectedEventSent:
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for first attack event")
	}

	// Check that no second event arrives
	select {
	case <-client.attackDetectedEventSent:
		t.Fatal("attack was reported more than once")
	case <-time.After(100 * time.Millisecond):
		// Success! No duplicate
	}
}

type mockCloudClient struct {
	attackDetectedEventSent chan struct{}
	capturedAgentInfo       cloud.AgentInfo
	capturedRequest         aikido_types.RequestInfo
	capturedAttack          aikido_types.AttackDetails
	mu                      sync.Mutex
}

func (m *mockCloudClient) SendStartEvent(agentInfo cloud.AgentInfo) {}
func (m *mockCloudClient) SendHeartbeatEvent(agentInfo cloud.AgentInfo, data cloud.HeartbeatData) time.Duration {
	return 0
}
func (m *mockCloudClient) CheckConfigUpdatedAt() time.Duration { return 0 }
func (m *mockCloudClient) SendAttackDetectedEvent(agentInfo cloud.AgentInfo, request aikido_types.RequestInfo, attack aikido_types.AttackDetails) {
	m.mu.Lock()
	m.capturedAgentInfo = agentInfo
	m.capturedRequest = request
	m.capturedAttack = attack
	m.mu.Unlock()

	m.attackDetectedEventSent <- struct{}{}
}

func TestExecContextShouldReturnError(t *testing.T) {
	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()

	// Enable blocking so that Zen should cause ExecContext to return an error
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

	req := httptest.NewRequest("GET", "/route?query=1%27%20OR%201%3D1", nil)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, "/route", "test", &ip, nil)

	db, err := sql.Open("test", "")
	require.NoError(t, err)

	request.WrapWithGLS(ctx, func() {
		result, err := db.ExecContext(ctx, "SELECT * FROM users WHERE id = '1' OR 1=1")
		require.Nil(t, result)
		require.Error(t, err)

		var detectedErr *vulnerabilities.AttackDetectedError
		require.ErrorAs(t, err, &detectedErr)

		var attackBlockedErr *zen.AttackBlockedError
		require.ErrorAs(t, err, &attackBlockedErr)
		require.Equal(t, zen.KindSQLInjection, attackBlockedErr.Kind)
	})
}
