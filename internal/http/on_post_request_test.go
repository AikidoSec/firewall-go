package http

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOnPostRequest_AttackWave(t *testing.T) {
	require.NoError(t, zen.Protect())

	block := true
	config.UpdateServiceConfig(&aikido_types.CloudConfigData{
		Block: &block,
	}, nil)

	original := agent.GetCloudClient()
	t.Cleanup(func() {
		agent.SetCloudClient(original)
	})

	client := &mockCloudClient{
		attackWaveDetectedEventSent: make(chan attackWaveDetails),
	}

	agent.SetCloudClient(client)

	for range 100 {
		req, _ := http.NewRequest("BADMETHOD", "/route", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		req.Header.Set("user-agent", "user-agent")

		ip := "10.0.0.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/route",
			RemoteAddress: &ip,
		})

		OnPostRequest(ctx, 200)
	}

	select {
	case result := <-client.attackWaveDetectedEventSent:
		// Success!
		assert.Equal(t, "10.0.0.1", result.ip)
		assert.Equal(t, "user-agent", result.userAgent)
		assert.Equal(t, "test", result.source)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("attack wave was never reported")
	}
}

type mockCloudClient struct {
	attackWaveDetectedEventSent chan attackWaveDetails
}

type attackWaveDetails struct {
	ip        string
	userAgent string
	source    string
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
	panic("not implemented")
}

func (m *mockCloudClient) SendAttackWaveDetectedEvent(agentInfo cloud.AgentInfo, request cloud.AttackWaveRequestInfo, attack cloud.AttackWaveDetails) {
	m.attackWaveDetectedEventSent <- attackWaveDetails{
		ip:        request.IPAddress,
		userAgent: request.UserAgent,
		source:    request.Source,
	}
}
