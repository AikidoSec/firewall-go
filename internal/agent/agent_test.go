package agent_test

import (
	"sync"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOnDomain(t *testing.T) {
	t.Run("calls storeDomain correctly", func(t *testing.T) {
		// Reset hostnames before test
		_ = agent.GetAndClearHostnames()

		agent.OnDomain("example.com", 443)

		hostnames := agent.GetAndClearHostnames()

		require.Contains(t, hostnames, aikido_types.Hostname{
			URL: "example.com", Port: 443, Hits: 1,
		}, "domain should be stored")
	})
}

type mockCloudClient struct{}

func (m *mockCloudClient) SendStartEvent(agentInfo cloud.AgentInfo) {}
func (m *mockCloudClient) SendHeartbeatEvent(agentInfo cloud.AgentInfo, data cloud.HeartbeatData) time.Duration {
	return 0
}
func (m *mockCloudClient) CheckConfigUpdatedAt() time.Duration { return 0 }
func (m *mockCloudClient) SendAttackDetectedEvent(agentInfo cloud.AgentInfo, request aikido_types.RequestInfo, attack aikido_types.AttackDetails) {
}

func TestCloudClient(t *testing.T) {
	original := agent.GetCloudClient()
	t.Cleanup(func() {
		agent.SetCloudClient(original)
	})

	t.Run("set and get client", func(t *testing.T) {
		mock := &mockCloudClient{}

		agent.SetCloudClient(mock)
		client := agent.GetCloudClient()

		assert.Equal(t, mock, client)
	})

	t.Run("set overwrites previous client", func(t *testing.T) {
		mock1 := &mockCloudClient{}
		mock2 := &mockCloudClient{}

		agent.SetCloudClient(mock1)
		agent.SetCloudClient(mock2)
		client := agent.GetCloudClient()

		assert.Equal(t, mock2, client)
	})

	t.Run("concurrent reads are safe", func(t *testing.T) {
		mock := &mockCloudClient{}
		agent.SetCloudClient(mock)

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				client := agent.GetCloudClient()
				assert.NotNil(t, client)
			}()
		}

		wg.Wait()
	})
}
