package agent

import (
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type pollingMockCloudClient struct {
	fetchConfigUpdatedAt time.Time
	fetchConfigResult    *aikido_types.CloudConfigData
	fetchConfigErr       error
	fetchListsResult     *aikido_types.ListsConfigData
	fetchListsErr        error
	heartbeatResult      *aikido_types.CloudConfigData
	heartbeatErr         error
	heartbeatCalled      bool
}

func (m *pollingMockCloudClient) SendStartEvent(agentInfo cloud.AgentInfo) (*aikido_types.CloudConfigData, error) {
	return nil, nil
}
func (m *pollingMockCloudClient) SendHeartbeatEvent(agentInfo cloud.AgentInfo, data cloud.HeartbeatData) (*aikido_types.CloudConfigData, error) {
	m.heartbeatCalled = true
	return m.heartbeatResult, m.heartbeatErr
}
func (m *pollingMockCloudClient) FetchConfigUpdatedAt() time.Time {
	return m.fetchConfigUpdatedAt
}
func (m *pollingMockCloudClient) FetchConfig() (*aikido_types.CloudConfigData, error) {
	return m.fetchConfigResult, m.fetchConfigErr
}
func (m *pollingMockCloudClient) FetchListsConfig() (*aikido_types.ListsConfigData, error) {
	if m.fetchListsResult != nil {
		return m.fetchListsResult, m.fetchListsErr
	}
	return &aikido_types.ListsConfigData{Success: true}, nil
}
func (m *pollingMockCloudClient) SendAttackDetectedEvent(agentInfo cloud.AgentInfo, request aikido_types.RequestInfo, attack aikido_types.AttackDetails) {
}
func (m *pollingMockCloudClient) SendAttackWaveDetectedEvent(agentInfo cloud.AgentInfo, req cloud.AttackWaveRequestInfo, attack cloud.AttackWaveDetails) {
}

func TestCalculateHeartbeatInterval(t *testing.T) {
	t.Run("returns 1 minute when no stats received yet", func(t *testing.T) {
		result := calculateHeartbeatInterval(300000, false)
		assert.Equal(t, 1*time.Minute, result)
	})

	t.Run("returns configured interval when stats received and interval >= minimum", func(t *testing.T) {
		result := calculateHeartbeatInterval(300000, true)
		assert.Equal(t, 300000*time.Millisecond, result)
	})

	t.Run("returns configured interval at exact minimum", func(t *testing.T) {
		result := calculateHeartbeatInterval(120000, true)
		assert.Equal(t, 120000*time.Millisecond, result)
	})

	t.Run("returns 0 when stats received but interval below minimum", func(t *testing.T) {
		result := calculateHeartbeatInterval(60000, true)
		assert.Equal(t, time.Duration(0), result)
	})

	t.Run("returns 0 when stats received and interval is 0", func(t *testing.T) {
		result := calculateHeartbeatInterval(0, true)
		assert.Equal(t, time.Duration(0), result)
	})
}

func TestResetHeartbeatTicker(t *testing.T) {
	t.Run("does not panic when heartbeatRoutine is nil", func(t *testing.T) {
		original := heartbeatRoutine
		heartbeatRoutine = nil
		t.Cleanup(func() { heartbeatRoutine = original })

		assert.NotPanics(t, func() {
			resetHeartbeatTicker(5 * time.Minute)
		})
	})

	t.Run("does not panic with zero interval", func(t *testing.T) {
		original := heartbeatRoutine
		heartbeatRoutine = nil
		t.Cleanup(func() { heartbeatRoutine = original })

		assert.NotPanics(t, func() {
			resetHeartbeatTicker(0)
		})
	})
}

func TestStopPolling(t *testing.T) {
	t.Run("does not panic when routines are nil", func(t *testing.T) {
		originalHb := heartbeatRoutine
		originalCp := configPollingRoutine
		heartbeatRoutine = nil
		configPollingRoutine = nil
		t.Cleanup(func() {
			heartbeatRoutine = originalHb
			configPollingRoutine = originalCp
		})

		assert.NotPanics(t, func() {
			stopPolling()
		})
	})
}

func TestRefreshCloudConfig(t *testing.T) {
	err := config.Init(&aikido_types.EnvironmentConfigData{}, &aikido_types.AikidoConfigData{LogLevel: "ERROR"})
	require.NoError(t, err)

	t.Run("does nothing when cloud client is nil", func(t *testing.T) {
		original := GetCloudClient()
		SetCloudClient(nil)
		t.Cleanup(func() { SetCloudClient(original) })

		assert.NotPanics(t, func() {
			refreshCloudConfig()
		})
	})

	t.Run("does nothing when config has not been updated", func(t *testing.T) {
		mock := &pollingMockCloudClient{
			fetchConfigUpdatedAt: time.Time{}, // zero time, not newer
		}
		original := GetCloudClient()
		SetCloudClient(mock)
		t.Cleanup(func() { SetCloudClient(original) })

		assert.NotPanics(t, func() {
			refreshCloudConfig()
		})
	})

	t.Run("fetches config when updated", func(t *testing.T) {
		mock := &pollingMockCloudClient{
			fetchConfigUpdatedAt: time.Now().Add(time.Hour),
			fetchConfigResult: &aikido_types.CloudConfigData{
				ConfigUpdatedAt: time.Now().Add(time.Hour).UnixMilli(),
			},
		}
		original := GetCloudClient()
		SetCloudClient(mock)
		t.Cleanup(func() { SetCloudClient(original) })

		assert.NotPanics(t, func() {
			refreshCloudConfig()
		})
	})
}

func TestSendHeartbeatEvent(t *testing.T) {
	err := config.Init(&aikido_types.EnvironmentConfigData{}, &aikido_types.AikidoConfigData{LogLevel: "ERROR"})
	require.NoError(t, err)

	t.Run("does nothing when cloud client is nil", func(t *testing.T) {
		original := GetCloudClient()
		SetCloudClient(nil)
		t.Cleanup(func() { SetCloudClient(original) })

		assert.NotPanics(t, func() {
			sendHeartbeatEvent()
		})
	})

	t.Run("sends heartbeat event", func(t *testing.T) {
		mock := &pollingMockCloudClient{
			heartbeatResult: &aikido_types.CloudConfigData{
				ConfigUpdatedAt: time.Now().Add(time.Hour).UnixMilli(),
			},
		}
		original := GetCloudClient()
		SetCloudClient(mock)
		t.Cleanup(func() { SetCloudClient(original) })

		sendHeartbeatEvent()
		assert.True(t, mock.heartbeatCalled)
	})
}
