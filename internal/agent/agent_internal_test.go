package agent

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/machine"
	"github.com/AikidoSec/firewall-go/internal/attackwave"
	"github.com/AikidoSec/firewall-go/internal/log"
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

func (m *internalMockCloudClient) SendCustomEvent(event cloud.CustomEvent) {
}

type trackingMockCloudClient struct {
	customEventCount int
}

func (m *trackingMockCloudClient) SendStartEvent(agentInfo cloud.AgentInfo) (*aikido_types.CloudConfigData, error) {
	return nil, nil
}
func (m *trackingMockCloudClient) SendHeartbeatEvent(agentInfo cloud.AgentInfo, data cloud.HeartbeatData) (*aikido_types.CloudConfigData, error) {
	return nil, nil
}
func (m *trackingMockCloudClient) FetchConfigUpdatedAt() time.Time { return time.Time{} }
func (m *trackingMockCloudClient) FetchConfig() (*aikido_types.CloudConfigData, error) {
	return nil, nil
}
func (m *trackingMockCloudClient) FetchListsConfig() (*aikido_types.ListsConfigData, error) {
	return nil, nil
}
func (m *trackingMockCloudClient) SendAttackDetectedEvent(agentInfo cloud.AgentInfo, request aikido_types.RequestInfo, attack aikido_types.AttackDetails) {
}
func (m *trackingMockCloudClient) SendAttackWaveDetectedEvent(agentInfo cloud.AgentInfo, req cloud.AttackWaveRequestInfo, attack cloud.AttackWaveDetails) {
}
func (m *trackingMockCloudClient) SubscribeToConfigUpdates(ctx context.Context, onUpdate func(int64)) error {
	return nil
}
func (m *trackingMockCloudClient) SendCustomEvent(event cloud.CustomEvent) {
	m.customEventCount++
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

func captureLogOutput(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	original := log.Logger()
	log.SetLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { log.SetLogger(original) })
	return &buf
}

func TestOnTrackEvent_CustomEventsDisabled(t *testing.T) {
	t.Cleanup(func() {
		customEventsDisabled.Store(false)
		customEventsWarnedOnce.Store(false)
	})

	t.Run("does not send event and logs warning when zen is unavailable", func(t *testing.T) {
		customEventsDisabled.Store(true)
		customEventsWarnedOnce.Store(false)

		buf := captureLogOutput(t)

		mock := &trackingMockCloudClient{}
		original := GetCloudClient()
		SetCloudClient(mock)
		t.Cleanup(func() { SetCloudClient(original) })

		OnTrackEvent("user.login", "user-1", "1.2.3.4", nil)
		time.Sleep(20 * time.Millisecond)

		assert.Equal(t, 0, mock.customEventCount)
		assert.Contains(t, buf.String(), "zen.aikido.dev")
	})

	t.Run("only logs warning once across multiple calls", func(t *testing.T) {
		customEventsDisabled.Store(true)
		customEventsWarnedOnce.Store(false)

		buf := captureLogOutput(t)

		OnTrackEvent("user.login", "", "", nil)
		OnTrackEvent("user.login", "", "", nil)
		OnTrackEvent("user.login", "", "", nil)

		warnCount := bytes.Count(buf.Bytes(), []byte("zen.aikido.dev"))
		assert.Equal(t, 1, warnCount)
	})

	t.Run("sends event normally when zen is available", func(t *testing.T) {
		customEventsDisabled.Store(false)
		customEventsWarnedOnce.Store(false)

		mock := &trackingMockCloudClient{}
		original := GetCloudClient()
		SetCloudClient(mock)
		t.Cleanup(func() { SetCloudClient(original) })

		OnTrackEvent("user.login", "user-1", "1.2.3.4", nil)
		time.Sleep(50 * time.Millisecond)

		assert.Equal(t, 1, mock.customEventCount)
	})
}
