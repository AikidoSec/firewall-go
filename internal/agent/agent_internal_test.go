package agent

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/machine"
	"github.com/AikidoSec/firewall-go/internal/attackwave"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAgentRuntime_OnOperationCall(t *testing.T) {
	rt := agentRuntime{}

	Stats().GetAndClear()
	rt.OnOperationCall("db.query", "sql_op")
	rt.OnOperationCall("db.query", "sql_op")

	snap := Stats().GetAndClear()
	require.Contains(t, snap.Operations, "db.query")
	assert.Equal(t, 2, snap.Operations["db.query"].Total)
}

func TestAgentRuntime_OnDomain(t *testing.T) {
	rt := agentRuntime{}
	_ = stateCollector.GetAndClearHostnames()

	rt.OnDomain("example.com", 443)

	hostnames := stateCollector.GetAndClearHostnames()
	require.Contains(t, hostnames, aikido_types.Hostname{URL: "example.com", Port: 443, Hits: 1})
}

func TestAgentRuntime_ShouldBlockHostname(t *testing.T) {
	rt := agentRuntime{}

	t.Run("returns false when no block list configured", func(t *testing.T) {
		assert.False(t, rt.ShouldBlockHostname("example.com"))
	})
}

func TestIsRealtimeEnabled(t *testing.T) {
	t.Run("returns true when AIKIDO_FEATURE_SSE is \"true\"", func(t *testing.T) {
		t.Setenv("AIKIDO_FEATURE_SSE", "true")
		assert.True(t, isRealtimeEnabled(&aikido_types.CloudConfigData{}))
	})

	t.Run("returns true when AIKIDO_FEATURE_SSE is \"1\"", func(t *testing.T) {
		t.Setenv("AIKIDO_FEATURE_SSE", "1")
		assert.True(t, isRealtimeEnabled(&aikido_types.CloudConfigData{}))
	})

	t.Run("returns true when AIKIDO_FEATURE_SSE is uppercase", func(t *testing.T) {
		t.Setenv("AIKIDO_FEATURE_SSE", "TRUE")
		assert.True(t, isRealtimeEnabled(&aikido_types.CloudConfigData{}))
	})

	t.Run("returns false when env var is empty", func(t *testing.T) {
		t.Setenv("AIKIDO_FEATURE_SSE", "")
		assert.False(t, isRealtimeEnabled(&aikido_types.CloudConfigData{}))
	})

	t.Run("returns false when env var is non-matching", func(t *testing.T) {
		t.Setenv("AIKIDO_FEATURE_SSE", "false")
		assert.False(t, isRealtimeEnabled(&aikido_types.CloudConfigData{}))
	})

	t.Run("returns false when cloud config is nil", func(t *testing.T) {
		t.Setenv("AIKIDO_FEATURE_SSE", "")
		assert.False(t, isRealtimeEnabled(nil))
	})

	t.Run("returns true when enabled features contains \"realtime_updates\"", func(t *testing.T) {
		t.Setenv("AIKIDO_FEATURE_SSE", "")
		assert.True(t, isRealtimeEnabled(&aikido_types.CloudConfigData{EnabledFeatures: []string{"realtime_updates"}}))
	})

	t.Run("returns false when enabled features does not contain \"realtime_updates\"", func(t *testing.T) {
		t.Setenv("AIKIDO_FEATURE_SSE", "")
		assert.False(t, isRealtimeEnabled(&aikido_types.CloudConfigData{EnabledFeatures: []string{"feature1", "feature2"}}))
	})
}

// resetAgentCtxForTest makes agentCtx bubble-local so synctest can track work started under it.
func resetAgentCtxForTest(t *testing.T) {
	t.Helper()
	originalCtx, originalCancel := agentCtx, agentCancel
	agentCtx, agentCancel = context.WithCancel(context.Background())
	t.Cleanup(func() {
		agentCancel()
		agentCtx, agentCancel = originalCtx, originalCancel
	})
}

func TestHandleStartEventConfig(t *testing.T) {
	initAgentForTest(t)

	t.Run("starts the SSE subscription when the initial cloud config enables realtime_updates", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			resetAgentCtxForTest(t)
			t.Setenv("AIKIDO_FEATURE_SSE", "")

			subscribed := false
			mock := &updatingMockCloudClient{
				subscribeFn: func(ctx context.Context, _ func(int64)) error {
					subscribed = true
					<-ctx.Done()
					return ctx.Err()
				},
			}
			original := GetCloudClient()
			SetCloudClient(mock)
			t.Cleanup(func() { SetCloudClient(original) })

			cloudConfig := &aikido_types.CloudConfigData{
				ConfigUpdatedAt: time.Now().Add(time.Hour).UnixMilli(),
				EnabledFeatures: []string{"realtime_updates"},
			}

			handleStartEventConfig(mock, cloudConfig)
			synctest.Wait()

			assert.True(t, subscribed)
		})
	})

	t.Run("cancelling agentCtx stops the SSE subscription", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			resetAgentCtxForTest(t)
			t.Setenv("AIKIDO_FEATURE_SSE", "")

			stopped := false
			mock := &updatingMockCloudClient{
				subscribeFn: func(ctx context.Context, _ func(int64)) error {
					<-ctx.Done()
					stopped = true
					return ctx.Err()
				},
			}
			original := GetCloudClient()
			SetCloudClient(mock)
			t.Cleanup(func() { SetCloudClient(original) })

			cloudConfig := &aikido_types.CloudConfigData{
				ConfigUpdatedAt: time.Now().Add(time.Hour).UnixMilli(),
				EnabledFeatures: []string{"realtime_updates"},
			}

			handleStartEventConfig(mock, cloudConfig)
			synctest.Wait()
			assert.False(t, stopped)

			agentCancel()
			synctest.Wait()
			assert.True(t, stopped)
		})
	})

	t.Run("does not start the SSE subscription when the initial cloud config does not enable realtime_updates", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			t.Setenv("AIKIDO_FEATURE_SSE", "")

			subscribed := false
			mock := &updatingMockCloudClient{
				subscribeFn: func(ctx context.Context, _ func(int64)) error {
					subscribed = true
					<-ctx.Done()
					return ctx.Err()
				},
			}
			original := GetCloudClient()
			SetCloudClient(mock)
			t.Cleanup(func() { SetCloudClient(original) })

			cloudConfig := &aikido_types.CloudConfigData{
				ConfigUpdatedAt: time.Now().Add(time.Hour).UnixMilli(),
			}

			handleStartEventConfig(mock, cloudConfig)
			synctest.Wait()

			assert.False(t, subscribed)
		})
	})
}

func TestAgentUninit(t *testing.T) {
	t.Run("sends a final heartbeat before tearing down background work", func(t *testing.T) {
		initAgentForTest(t)
		resetAgentCtxForTest(t)

		mock := &updatingMockCloudClient{
			heartbeatResult: &aikido_types.CloudConfigData{
				ConfigUpdatedAt: time.Now().Add(time.Hour).UnixMilli(),
			},
		}
		original := GetCloudClient()
		SetCloudClient(mock)
		t.Cleanup(func() { SetCloudClient(original) })

		err := AgentUninit()

		require.NoError(t, err)
		assert.True(t, mock.heartbeatCalled)
	})

	t.Run("does not panic when cloud client is nil", func(t *testing.T) {
		resetAgentCtxForTest(t)

		original := GetCloudClient()
		SetCloudClient(nil)
		t.Cleanup(func() { SetCloudClient(original) })

		assert.NotPanics(t, func() {
			err := AgentUninit()
			assert.NoError(t, err)
		})
	})
}

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
func (m *internalMockCloudClient) SubscribeToConfigUpdates(ctx context.Context, onUpdate func(int64)) error {
	return nil
}

func TestState(t *testing.T) {
	t.Run("returns non-nil state collector", func(t *testing.T) {
		assert.NotNil(t, State())
	})
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

func initAgentForTest(t *testing.T) {
	t.Helper()
	machine.Init()
	err := config.Init(&aikido_types.EnvironmentConfigData{}, &aikido_types.AikidoConfigData{LogLevel: "ERROR"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestOnAttackDetected(t *testing.T) {
	initAgentForTest(t)

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

func TestOnOperationAttack(t *testing.T) {
	t.Run("records operation attack in stats", func(t *testing.T) {
		assert.NotPanics(t, func() {
			OnOperationAttack("db.query", true)
		})
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
		result := CheckAttackWave(nil, 200)
		assert.False(t, result)
	})

	t.Run("returns false for clean request", func(t *testing.T) {
		ctx := &request.Context{
			Method: "GET",
			URL:    "/clean",
		}
		result := CheckAttackWave(ctx, 200)
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
		initAgentForTest(t)

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

	t.Run("increments attack waves stat", func(t *testing.T) {
		initAgentForTest(t)
		Stats().GetAndClear()

		ip := "1.2.3.4"
		ctx := &request.Context{
			RemoteAddress: &ip,
			Source:        "test",
		}

		OnAttackWaveDetected(ctx)

		snap := Stats().GetAndClear()
		assert.Equal(t, 1, snap.Requests.AttackWaves.Total)
	})

	t.Run("includes samples in metadata when available", func(t *testing.T) {
		// Use a detector with a low threshold so we can trigger sample collection
		originalDetector := attackWaveDetector
		attackWaveDetector = attackwave.NewDetector(&attackwave.Options{
			AttackWaveThreshold: 1,
			MaxSamplesPerIP:     5,
		})
		t.Cleanup(func() { attackWaveDetector = originalDetector })

		ip := "10.0.0.1"
		scanCtx := &request.Context{
			RemoteAddress: &ip,
			Method:        "GET",
			Path:          "/.env",
			URL:           "http://example.com/.env",
		}
		attackWaveDetector.CheckRequest(scanCtx, 404)

		ctx := &request.Context{
			RemoteAddress: &ip,
			Source:        "test",
		}

		assert.NotPanics(t, func() {
			OnAttackWaveDetected(ctx)
		})
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
