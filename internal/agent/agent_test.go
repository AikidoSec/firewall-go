package agent_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/AikidoSec/firewall-go/internal/agent/state/stats"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOnAICall(t *testing.T) {
	agent.Stats().GetAndClearAI()

	agent.OnAICall(stats.AICallData{
		Provider:     "anthropic",
		Model:        "claude-3",
		InputTokens:  200,
		OutputTokens: 75,
	})

	snap := agent.Stats().GetAndClearAI()
	require.Len(t, snap, 1)
	assert.Equal(t, "anthropic", snap[0].Provider)
	assert.Equal(t, "claude-3", snap[0].Model)
	assert.Equal(t, 1, snap[0].Calls)
	assert.Equal(t, 200, snap[0].Tokens.Input)
	assert.Equal(t, 75, snap[0].Tokens.Output)
	assert.Equal(t, 275, snap[0].Tokens.Total)
}

type mockCloudClient struct{}

func (m *mockCloudClient) SendStartEvent(agentInfo cloud.AgentInfo) (*aikido_types.CloudConfigData, error) {
	panic("not implemented")
}

func (m *mockCloudClient) SendHeartbeatEvent(ctx context.Context, agentInfo cloud.AgentInfo, data cloud.HeartbeatData) (*aikido_types.CloudConfigData, error) {
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

func (m *mockCloudClient) SendAttackWaveDetectedEvent(agentInfo cloud.AgentInfo, request cloud.AttackWaveRequestInfo, attack cloud.AttackWaveDetails) {
}
func (m *mockCloudClient) SubscribeToConfigUpdates(ctx context.Context, onUpdate func(int64)) error {
	panic("not implemented")
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
