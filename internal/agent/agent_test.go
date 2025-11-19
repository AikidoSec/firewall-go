package agent_test

import (
	"sync"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/stretchr/testify/assert"
)

type mockCloudClient struct{}

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
