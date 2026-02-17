package agent

import (
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/ratelimiting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type configTestCloudClient struct {
	fetchListsConfigFunc func() (*aikido_types.ListsConfigData, error)
}

func (m *configTestCloudClient) SendStartEvent(agentInfo cloud.AgentInfo) (*aikido_types.CloudConfigData, error) {
	return nil, nil
}
func (m *configTestCloudClient) SendHeartbeatEvent(agentInfo cloud.AgentInfo, data cloud.HeartbeatData) (*aikido_types.CloudConfigData, error) {
	return nil, nil
}
func (m *configTestCloudClient) FetchConfigUpdatedAt() time.Time { return time.Time{} }
func (m *configTestCloudClient) FetchConfig() (*aikido_types.CloudConfigData, error) {
	return nil, nil
}
func (m *configTestCloudClient) FetchListsConfig() (*aikido_types.ListsConfigData, error) {
	if m.fetchListsConfigFunc != nil {
		return m.fetchListsConfigFunc()
	}
	return &aikido_types.ListsConfigData{Success: true}, nil
}
func (m *configTestCloudClient) SendAttackDetectedEvent(agentInfo cloud.AgentInfo, request aikido_types.RequestInfo, attack aikido_types.AttackDetails) {
}
func (m *configTestCloudClient) SendAttackWaveDetectedEvent(agentInfo cloud.AgentInfo, request cloud.AttackWaveRequestInfo, attack cloud.AttackWaveDetails) {
}

func TestApplyCloudConfig(t *testing.T) {
	err := config.Init(&aikido_types.EnvironmentConfigData{}, &aikido_types.AikidoConfigData{LogLevel: "ERROR"})
	require.NoError(t, err)

	t.Run("does nothing when cloudConfig is nil", func(t *testing.T) {
		client := &configTestCloudClient{}
		assert.NotPanics(t, func() {
			applyCloudConfig(client, nil)
		})
	})

	t.Run("does nothing when cloudConfig is not newer", func(t *testing.T) {
		client := &configTestCloudClient{}
		// ConfigUpdatedAt of 0 should not be newer than current
		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt: 0,
		}
		assert.NotPanics(t, func() {
			applyCloudConfig(client, cloudConfig)
		})
	})

	t.Run("applies config when newer", func(t *testing.T) {
		client := &configTestCloudClient{}
		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt:       time.Now().Add(time.Hour).UnixMilli(),
			HeartbeatIntervalInMS: 300000,
			ReceivedAnyStats:      true,
			Endpoints: []aikido_types.Endpoint{
				{
					Method: "GET",
					Route:  "/api/test",
					RateLimiting: aikido_types.RateLimiting{
						Enabled:        true,
						MaxRequests:    100,
						WindowSizeInMS: 60000,
					},
				},
			},
		}
		assert.NotPanics(t, func() {
			applyCloudConfig(client, cloudConfig)
		})
	})
}

func TestUpdateRateLimitingConfig(t *testing.T) {
	ratelimiting.Init()
	t.Cleanup(func() { ratelimiting.Uninit() })

	t.Run("converts endpoints to rate limiting config", func(t *testing.T) {
		endpoints := []aikido_types.Endpoint{
			{
				Method: "GET",
				Route:  "/api/users",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    50,
					WindowSizeInMS: 30000,
				},
			},
			{
				Method: "POST",
				Route:  "/api/login",
				RateLimiting: aikido_types.RateLimiting{
					Enabled:        true,
					MaxRequests:    5,
					WindowSizeInMS: 60000,
				},
			},
		}

		assert.NotPanics(t, func() {
			updateRateLimitingConfig(endpoints)
		})
	})

	t.Run("handles empty endpoints", func(t *testing.T) {
		assert.NotPanics(t, func() {
			updateRateLimitingConfig(nil)
		})
	})
}
