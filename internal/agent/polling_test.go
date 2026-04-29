package agent

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type pollingMockCloudClient struct {
	fetchConfigUpdatedAt  time.Time
	fetchConfigResult     *aikido_types.CloudConfigData
	fetchConfigErr        error
	fetchConfigCallCount  int
	fetchListsResult      *aikido_types.ListsConfigData
	fetchListsErr         error
	heartbeatResult       *aikido_types.CloudConfigData
	heartbeatErr          error
	heartbeatCalled       bool
	subscribeFn           func(ctx context.Context, onUpdate func(int64)) error
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
	m.fetchConfigCallCount++
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
func (m *pollingMockCloudClient) SubscribeToConfigUpdates(ctx context.Context, onUpdate func(int64)) error {
	if m.subscribeFn != nil {
		return m.subscribeFn(ctx, onUpdate)
	}
	return nil
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

func TestRefreshCloudConfigIfNewer(t *testing.T) {
	err := config.Init(&aikido_types.EnvironmentConfigData{}, &aikido_types.AikidoConfigData{LogLevel: "ERROR"})
	require.NoError(t, err)

	t.Run("does nothing when client is nil", func(t *testing.T) {
		original := GetCloudClient()
		SetCloudClient(nil)
		t.Cleanup(func() { SetCloudClient(original) })

		assert.NotPanics(t, func() {
			refreshCloudConfigIfNewer(time.Now().Add(time.Hour).UnixMilli())
		})
	})

	resetConfigUpdatedAt := func(t *testing.T) {
		t.Helper()
		config.UpdateServiceConfig(&aikido_types.CloudConfigData{ConfigUpdatedAt: 0}, &aikido_types.ListsConfigData{})
	}

	t.Run("skips fetch when timestamp is not newer than stored", func(t *testing.T) {
		futureTs := time.Now().Add(time.Hour).UnixMilli()
		config.UpdateServiceConfig(
			&aikido_types.CloudConfigData{ConfigUpdatedAt: futureTs},
			&aikido_types.ListsConfigData{},
		)
		t.Cleanup(func() { resetConfigUpdatedAt(t) })

		mock := &pollingMockCloudClient{}
		original := GetCloudClient()
		SetCloudClient(mock)
		t.Cleanup(func() { SetCloudClient(original) })

		refreshCloudConfigIfNewer(time.Now().UnixMilli())
		assert.Equal(t, 0, mock.fetchConfigCallCount)
	})

	t.Run("fetches and applies config when timestamp is newer", func(t *testing.T) {
		resetConfigUpdatedAt(t)

		mock := &pollingMockCloudClient{
			fetchConfigResult: &aikido_types.CloudConfigData{
				ConfigUpdatedAt: time.Now().Add(time.Hour).UnixMilli(),
			},
		}
		original := GetCloudClient()
		SetCloudClient(mock)
		t.Cleanup(func() { SetCloudClient(original) })

		refreshCloudConfigIfNewer(time.Now().Add(time.Hour).UnixMilli())
		assert.Equal(t, 1, mock.fetchConfigCallCount)
	})

	t.Run("does not panic on fetch error", func(t *testing.T) {
		resetConfigUpdatedAt(t)

		mock := &pollingMockCloudClient{
			fetchConfigErr: errors.New("network error"),
		}
		original := GetCloudClient()
		SetCloudClient(mock)
		t.Cleanup(func() { SetCloudClient(original) })

		assert.NotPanics(t, func() {
			refreshCloudConfigIfNewer(time.Now().Add(time.Hour).UnixMilli())
		})
		assert.Equal(t, 1, mock.fetchConfigCallCount)
	})
}

func TestRunSSESubscription(t *testing.T) {
	t.Run("exits when context is cancelled", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			mock := &pollingMockCloudClient{
				subscribeFn: func(ctx context.Context, _ func(int64)) error {
					<-ctx.Done()
					return ctx.Err()
				},
			}
			original := GetCloudClient()
			SetCloudClient(mock)
			t.Cleanup(func() { SetCloudClient(original) })

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				runSSESubscription(ctx)
			}()

			synctest.Wait()
			cancel()
			<-done
		})
	})

	t.Run("exits immediately on non-retryable error", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			mock := &pollingMockCloudClient{
				subscribeFn: func(_ context.Context, _ func(int64)) error {
					return cloud.ErrNotRetryable
				},
			}
			original := GetCloudClient()
			SetCloudClient(mock)
			t.Cleanup(func() { SetCloudClient(original) })

			done := make(chan struct{})
			go func() {
				defer close(done)
				runSSESubscription(context.Background())
			}()

			<-done
		})
	})

	t.Run("reconnects after transient error", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			callCount := 0
			mock := &pollingMockCloudClient{
				subscribeFn: func(_ context.Context, _ func(int64)) error {
					callCount++
					if callCount == 1 {
						return errors.New("transient error")
					}
					return cloud.ErrNotRetryable
				},
			}
			original := GetCloudClient()
			SetCloudClient(mock)
			t.Cleanup(func() { SetCloudClient(original) })

			done := make(chan struct{})
			go func() {
				defer close(done)
				runSSESubscription(context.Background())
			}()

			<-done
			assert.Equal(t, 2, callCount)
		})
	})

	t.Run("reconnects on clean close", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			callCount := 0
			mock := &pollingMockCloudClient{
				subscribeFn: func(_ context.Context, _ func(int64)) error {
					callCount++
					if callCount == 1 {
						return nil
					}
					return cloud.ErrNotRetryable
				},
			}
			original := GetCloudClient()
			SetCloudClient(mock)
			t.Cleanup(func() { SetCloudClient(original) })

			done := make(chan struct{})
			go func() {
				defer close(done)
				runSSESubscription(context.Background())
			}()

			<-done
			assert.Equal(t, 2, callCount)
		})
	})

	t.Run("exits during nil-client backoff wait when context is cancelled", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			original := GetCloudClient()
			SetCloudClient(nil)
			t.Cleanup(func() { SetCloudClient(original) })

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				runSSESubscription(ctx)
			}()

			synctest.Wait()
			cancel()
			<-done
		})
	})
}
