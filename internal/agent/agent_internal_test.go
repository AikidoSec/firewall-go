package agent

import (
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/AikidoSec/firewall-go/internal/agent/state/stats"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOnMiddlewareInstalled(t *testing.T) {
	t.Run("sets MiddlewareInstalled to 1", func(t *testing.T) {
		// Reset the value before test
		stateCollector.SetMiddlewareInstalled(false)

		OnMiddlewareInstalled()

		value := stateCollector.IsMiddlewareInstalled()
		assert.True(t, value, "MiddlewareInstalled should be true")
	})

	t.Run("can be called multiple times", func(t *testing.T) {
		// Reset the value before test
		stateCollector.SetMiddlewareInstalled(false)

		OnMiddlewareInstalled()
		OnMiddlewareInstalled()
		OnMiddlewareInstalled()

		value := stateCollector.IsMiddlewareInstalled()
		assert.True(t, value, "MiddlewareInstalled should remain true")
	})
}

func TestOnDomain(t *testing.T) {
	t.Run("calls storeDomain correctly", func(t *testing.T) {
		// Reset hostnames before test
		_ = stateCollector.GetAndClearHostnames()

		OnDomain("example.com", 443)

		hostnames := stateCollector.GetAndClearHostnames()

		require.Contains(t, hostnames, aikido_types.Hostname{
			URL: "example.com", Port: 443, Hits: 1,
		}, "domain should be stored")
	})
}

type internalMockCloudClient struct {
	sendAttackDetectedCalled     bool
	sendAttackWaveDetectedCalled bool
}

func (m *internalMockCloudClient) SendStartEvent(agentInfo cloud.AgentInfo) (*aikido_types.CloudConfigData, error) {
	return nil, nil
}
func (m *internalMockCloudClient) SendHeartbeatEvent(agentInfo cloud.AgentInfo, data cloud.HeartbeatData) (*aikido_types.CloudConfigData, error) {
	return nil, nil
}
func (m *internalMockCloudClient) FetchConfigUpdatedAt() time.Time { return time.Time{} }
func (m *internalMockCloudClient) FetchConfig() (*aikido_types.CloudConfigData, error) {
	return nil, nil
}
func (m *internalMockCloudClient) FetchListsConfig() (*aikido_types.ListsConfigData, error) {
	return nil, nil
}
func (m *internalMockCloudClient) SendAttackDetectedEvent(agentInfo cloud.AgentInfo, request aikido_types.RequestInfo, attack aikido_types.AttackDetails) {
	m.sendAttackDetectedCalled = true
}
func (m *internalMockCloudClient) SendAttackWaveDetectedEvent(agentInfo cloud.AgentInfo, req cloud.AttackWaveRequestInfo, attack cloud.AttackWaveDetails) {
	m.sendAttackWaveDetectedCalled = true
}

func TestOnUser(t *testing.T) {
	t.Cleanup(func() { stateCollector.GetUsersAndClear() })

	t.Run("returns user with correct fields", func(t *testing.T) {
		stateCollector.GetUsersAndClear()
		user := OnUser("id1", "TestUser", "10.0.0.1")

		assert.Equal(t, "id1", user.ID)
		assert.Equal(t, "TestUser", user.Name)
		assert.Equal(t, "10.0.0.1", user.LastIpAddress)
	})
}

func TestOnAttackDetected(t *testing.T) {
	t.Run("sends event to cloud client and updates stats", func(t *testing.T) {
		mock := &internalMockCloudClient{}
		original := GetCloudClient()
		SetCloudClient(mock)
		t.Cleanup(func() { SetCloudClient(original) })

		attack := &DetectedAttack{
			Request: aikido_types.RequestInfo{
				Method: "GET",
				URL:    "/test",
			},
			Attack: aikido_types.AttackDetails{
				Kind:    "sql_injection",
				Blocked: true,
			},
		}

		OnAttackDetected(attack)
		assert.True(t, mock.sendAttackDetectedCalled)
	})

	t.Run("does not panic when cloud client is nil", func(t *testing.T) {
		original := GetCloudClient()
		SetCloudClient(nil)
		t.Cleanup(func() { SetCloudClient(original) })

		attack := &DetectedAttack{
			Attack: aikido_types.AttackDetails{Blocked: false},
		}

		assert.NotPanics(t, func() {
			OnAttackDetected(attack)
		})
	})
}

func TestOnOperationCall(t *testing.T) {
	t.Run("records operation call in stats", func(t *testing.T) {
		assert.NotPanics(t, func() {
			OnOperationCall("db.query", stats.OperationKindSQL)
		})
	})
}

func TestOnOperationAttack(t *testing.T) {
	t.Run("records operation attack in stats", func(t *testing.T) {
		assert.NotPanics(t, func() {
			OnOperationAttack("db.query", true)
		})
	})
}

func TestState(t *testing.T) {
	t.Run("returns non-nil state collector", func(t *testing.T) {
		assert.NotNil(t, State())
	})
}

func TestStats(t *testing.T) {
	t.Run("returns non-nil stats", func(t *testing.T) {
		assert.NotNil(t, Stats())
	})
}

func TestOnRequestShutdown(t *testing.T) {
	t.Run("records request metadata", func(t *testing.T) {
		assert.NotPanics(t, func() {
			OnRequestShutdown("GET", "/api/test", 200, "user1", "1.2.3.4", nil)
		})
	})
}

func TestGetRateLimitingStatus(t *testing.T) {
	t.Run("returns status for request", func(t *testing.T) {
		status := GetRateLimitingStatus("GET", "/api/test", "user1", "1.2.3.4", "")
		assert.NotNil(t, status)
		assert.False(t, status.Block)
	})
}

func TestCheckAttackWave(t *testing.T) {
	t.Run("returns false for nil context", func(t *testing.T) {
		result := CheckAttackWave(nil)
		assert.False(t, result)
	})

	t.Run("returns false for clean request", func(t *testing.T) {
		ctx := &request.Context{
			Method: "GET",
			URL:    "/clean",
		}
		result := CheckAttackWave(ctx)
		assert.False(t, result)
	})
}

func TestOnAttackWaveDetected(t *testing.T) {
	t.Run("does not panic when context is nil", func(t *testing.T) {
		assert.NotPanics(t, func() {
			OnAttackWaveDetected(nil)
		})
	})

	t.Run("sends event when cloud client is set", func(t *testing.T) {
		mock := &internalMockCloudClient{}
		original := GetCloudClient()
		SetCloudClient(mock)
		t.Cleanup(func() { SetCloudClient(original) })

		ip := "1.2.3.4"
		ctx := &request.Context{
			RemoteAddress: &ip,
			Headers:       map[string][]string{"user-agent": {"test-agent"}},
			Source:        "test",
		}

		OnAttackWaveDetected(ctx)
		assert.True(t, mock.sendAttackWaveDetectedCalled)
	})

	t.Run("does not panic when cloud client is nil", func(t *testing.T) {
		original := GetCloudClient()
		SetCloudClient(nil)
		t.Cleanup(func() { SetCloudClient(original) })

		ip := "1.2.3.4"
		ctx := &request.Context{
			RemoteAddress: &ip,
			Source:        "test",
		}

		assert.NotPanics(t, func() {
			OnAttackWaveDetected(ctx)
		})
	})
}
