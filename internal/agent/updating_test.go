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

type updatingMockCloudClient struct {
	fetchConfigUpdatedAt time.Time
	fetchConfigResult    *aikido_types.CloudConfigData
	fetchConfigErr       error
	fetchConfigCallCount int
	fetchListsResult     *aikido_types.ListsConfigData
	fetchListsErr        error
	heartbeatResult      *aikido_types.CloudConfigData
	heartbeatErr         error
	heartbeatCalled      bool
	heartbeatFn          func(ctx context.Context) (*aikido_types.CloudConfigData, error)
	subscribeFn          func(ctx context.Context, onUpdate func(int64)) error
}

func (m *updatingMockCloudClient) SendStartEvent(agentInfo cloud.AgentInfo) (*aikido_types.CloudConfigData, error) {
	return nil, nil
}
func (m *updatingMockCloudClient) SendHeartbeatEvent(ctx context.Context, agentInfo cloud.AgentInfo, data cloud.HeartbeatData) (*aikido_types.CloudConfigData, error) {
	m.heartbeatCalled = true
	if m.heartbeatFn != nil {
		return m.heartbeatFn(ctx)
	}
	return m.heartbeatResult, m.heartbeatErr
}
func (m *updatingMockCloudClient) FetchConfigUpdatedAt() time.Time {
	return m.fetchConfigUpdatedAt
}
func (m *updatingMockCloudClient) FetchConfig() (*aikido_types.CloudConfigData, error) {
	m.fetchConfigCallCount++
	return m.fetchConfigResult, m.fetchConfigErr
}
func (m *updatingMockCloudClient) FetchListsConfig() (*aikido_types.ListsConfigData, error) {
	if m.fetchListsResult != nil {
		return m.fetchListsResult, m.fetchListsErr
	}
	return &aikido_types.ListsConfigData{Success: true}, nil
}
func (m *updatingMockCloudClient) SendAttackDetectedEvent(agentInfo cloud.AgentInfo, request aikido_types.RequestInfo, attack aikido_types.AttackDetails) {
}
func (m *updatingMockCloudClient) SendAttackWaveDetectedEvent(agentInfo cloud.AgentInfo, req cloud.AttackWaveRequestInfo, attack cloud.AttackWaveDetails) {
}
func (m *updatingMockCloudClient) SubscribeToConfigUpdates(ctx context.Context, onUpdate func(int64)) error {
	if m.subscribeFn != nil {
		return m.subscribeFn(ctx, onUpdate)
	}
	return nil
}

func resetHeartbeatSchedule(t *testing.T) {
	t.Helper()
	origCounter := heartbeatCounter.Load()
	origInterval := steadyHeartbeatInterval.Load()
	heartbeatCounter.Store(0)
	steadyHeartbeatInterval.Store(int64(defaultHeartbeatInterval))

	t.Cleanup(func() {
		heartbeatCounter.Store(origCounter)
		steadyHeartbeatInterval.Store(origInterval)
	})
}

func TestHeartbeatInterval(t *testing.T) {
	resetHeartbeatSchedule(t)

	t.Run("returns 30 seconds for the first heartbeat", func(t *testing.T) {
		heartbeatCounter.Store(0)

		assert.Equal(t, 30*time.Second, heartbeatInterval())
	})

	t.Run("returns 2 minutes for the second heartbeat", func(t *testing.T) {
		heartbeatCounter.Store(1)

		assert.Equal(t, 2*time.Minute, heartbeatInterval())
	})

	t.Run("returns the steady-state interval from the third heartbeat onward", func(t *testing.T) {
		heartbeatCounter.Store(2)
		steadyHeartbeatInterval.Store(int64(5 * time.Minute))

		assert.Equal(t, 5*time.Minute, heartbeatInterval())

		heartbeatCounter.Store(10)

		assert.Equal(t, 5*time.Minute, heartbeatInterval())
	})
}

func TestAdvanceHeartbeatSchedule(t *testing.T) {
	resetHeartbeatSchedule(t)

	t.Run("increments the counter on every call, regardless of send outcome", func(t *testing.T) {
		heartbeatCounter.Store(0)

		advanceHeartbeatSchedule()
		assert.Equal(t, int64(1), heartbeatCounter.Load())

		advanceHeartbeatSchedule()
		assert.Equal(t, int64(2), heartbeatCounter.Load())
	})
}

func TestUpdateSteadyHeartbeatInterval(t *testing.T) {
	resetHeartbeatSchedule(t)

	t.Run("ignores intervals below the minimum", func(t *testing.T) {
		steadyHeartbeatInterval.Store(int64(10 * time.Minute))

		updateSteadyHeartbeatInterval(60000)

		assert.Equal(t, 10*time.Minute, time.Duration(steadyHeartbeatInterval.Load()))
	})

	t.Run("applies intervals at or above the minimum", func(t *testing.T) {
		updateSteadyHeartbeatInterval(300000)

		assert.Equal(t, 300000*time.Millisecond, time.Duration(steadyHeartbeatInterval.Load()))
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
		mock := &updatingMockCloudClient{
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
		mock := &updatingMockCloudClient{
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
			sendHeartbeatEvent(context.Background())
		})
	})

	t.Run("sends heartbeat event", func(t *testing.T) {
		mock := &updatingMockCloudClient{
			heartbeatResult: &aikido_types.CloudConfigData{
				ConfigUpdatedAt: time.Now().Add(time.Hour).UnixMilli(),
			},
		}
		original := GetCloudClient()
		SetCloudClient(mock)
		t.Cleanup(func() { SetCloudClient(original) })

		sendHeartbeatEvent(context.Background())
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

		mock := &updatingMockCloudClient{}
		original := GetCloudClient()
		SetCloudClient(mock)
		t.Cleanup(func() { SetCloudClient(original) })

		refreshCloudConfigIfNewer(time.Now().UnixMilli())
		assert.Equal(t, 0, mock.fetchConfigCallCount)
	})

	t.Run("fetches and applies config when timestamp is newer", func(t *testing.T) {
		resetConfigUpdatedAt(t)

		mock := &updatingMockCloudClient{
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

		mock := &updatingMockCloudClient{
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
			mock := &updatingMockCloudClient{
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
			mock := &updatingMockCloudClient{
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
			mock := &updatingMockCloudClient{
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
			mock := &updatingMockCloudClient{
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
