package vulnerabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetDisplayNameForAttackKind(t *testing.T) {
	tests := []struct {
		name     string
		kind     AttackKind
		expected string
	}{
		{"SQLInjection", KindSQLInjection, "an SQL injection"},
		{"PathTraversal", KindPathTraversal, "a path traversal attack"},
		{"ShellInjection", KindShellInjection, "a shell injection"},
		{"SSRF", KindSSRF, "a server-side request forgery"},
		{"StoredSSRF", KindStoredSSRF, "a stored server-side request forgery"},
		{"Unknown", AttackKind("unknown"), "unknown attack type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getDisplayNameForAttackKind(tt.kind)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestInterceptorResultToString(t *testing.T) {
	tests := []struct {
		name     string
		result   interceptorResult
		expected string
	}{
		{
			name: "valid JSON",
			result: interceptorResult{
				Kind:          KindSQLInjection,
				Operation:     "exec",
				Source:        "body",
				PathToPayload: ".query.id",
				Payload:       "1 OR 1=1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.result.ToString()

			// Verify it's valid JSON
			var decoded interceptorResult
			err := json.Unmarshal([]byte(result), &decoded)
			require.NoError(t, err)

			// Verify the decoded values match
			assert.Equal(t, tt.result.Kind, decoded.Kind)
			assert.Equal(t, tt.result.Operation, decoded.Operation)
		})
	}
}

func TestBuildAttackDetectedError(t *testing.T) {
	result := interceptorResult{
		Kind:          KindPathTraversal,
		Operation:     "readFile",
		Source:        "query",
		PathToPayload: "../etc/passwd",
		Payload:       "../../etc/passwd",
	}

	err := buildAttackDetectedError(result)
	require.Error(t, err)

	errorMsg := err.Error()
	assert.Contains(t, errorMsg, "a path traversal attack")
	assert.Contains(t, errorMsg, "readFile")
	assert.Contains(t, errorMsg, "query")
}

func TestGetAttackDetected(t *testing.T) {
	ip := "127.0.0.1"
	req := httptest.NewRequest("POST", "/api/users", http.NoBody)
	req.Header.Set("Content-Type", "application/json")

	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/api/users",
		RemoteAddress: &ip,
		Body:          map[string]interface{}{"name": "test"},
	})

	result := interceptorResult{
		Kind:          KindSQLInjection,
		Operation:     "query",
		Source:        "body",
		PathToPayload: ".name",
		Payload:       "1 OR 1=1",
		Metadata:      map[string]string{"key": "value"},
	}

	atk := getAttackDetected(ctx, result)
	require.NotNil(t, atk)

	assert.Equal(t, ip, atk.Request.IPAddress)
	assert.Equal(t, "POST", atk.Request.Method)
	assert.Equal(t, string(KindSQLInjection), atk.Attack.Kind)
	assert.Equal(t, "query", atk.Attack.Operation)

	// Verify metadata is cloned
	atk.Attack.Metadata["key"] = "modified"
	assert.Equal(t, "value", result.Metadata["key"], "Metadata should be cloned, not referenced")
}

func TestGetAttackDetectedWithNilContext(t *testing.T) {
	result := interceptorResult{
		Kind:      KindSQLInjection,
		Operation: "query",
	}

	atk := getAttackDetected(context.TODO(), result)
	assert.Nil(t, atk)

	atk = getAttackDetected(context.Background(), result)
	assert.Nil(t, atk)
}

func TestOnInterceptorResultWithNilResult(t *testing.T) {
	err := onInterceptorResult(context.Background(), nil)
	assert.NoError(t, err)
}

func TestStoreDeferredAttack(t *testing.T) {
	t.Run("returns nil when result is nil", func(t *testing.T) {
		err := storeDeferredAttack(context.Background(), nil)
		assert.NoError(t, err)
	})

	t.Run("returns nil when context has no request context", func(t *testing.T) {
		result := &interceptorResult{
			Kind:      KindPathTraversal,
			Operation: "filepath.Join",
		}
		err := storeDeferredAttack(context.Background(), result)
		assert.NoError(t, err)
	})

	t.Run("stores attack and error in context", func(t *testing.T) {
		ip := "127.0.0.1"
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/test",
			RemoteAddress: &ip,
		})

		result := &interceptorResult{
			Kind:          KindPathTraversal,
			Operation:     "filepath.Join",
			Source:        "query",
			PathToPayload: ".path",
			Payload:       "../etc/passwd",
			Metadata:      map[string]string{"filename": "/tmp/../etc/passwd"},
		}

		original := config.IsBlockingEnabled()
		config.SetBlocking(true)
		defer config.SetBlocking(original)

		err := storeDeferredAttack(ctx, result)
		assert.NoError(t, err)

		reqCtx := request.GetContext(ctx)
		require.NotNil(t, reqCtx)
		deferredAttack := reqCtx.GetDeferredAttack()
		require.NotNil(t, deferredAttack)

		assert.Equal(t, "filepath.Join", deferredAttack.Operation)
		assert.Equal(t, string(KindPathTraversal), deferredAttack.Kind)
		assert.Equal(t, "../etc/passwd", deferredAttack.Payload)
		assert.NotNil(t, deferredAttack.Error)
		assert.Contains(t, deferredAttack.Error.Error(), "path traversal attack")
	})

	t.Run("does not store error when blocking is disabled", func(t *testing.T) {
		ip := "127.0.0.1"
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/test",
			RemoteAddress: &ip,
		})

		result := &interceptorResult{
			Kind:          KindPathTraversal,
			Operation:     "filepath.Join",
			Source:        "query",
			PathToPayload: ".path",
			Payload:       "../etc/passwd",
		}

		original := config.IsBlockingEnabled()
		config.SetBlocking(false)
		defer config.SetBlocking(original)

		err := storeDeferredAttack(ctx, result)
		assert.NoError(t, err)

		reqCtx := request.GetContext(ctx)
		deferredAttack := reqCtx.GetDeferredAttack()
		require.NotNil(t, deferredAttack)
		assert.Nil(t, deferredAttack.Error, "Error should not be stored when attack is not intended to be blocked")
	})
}

func TestReportDeferredAttack(t *testing.T) {
	require.NoError(t, agent.Init(&aikido_types.EnvironmentConfigData{}, &aikido_types.AikidoConfigData{}))

	t.Run("does nothing when context has no request context", func(t *testing.T) {
		originalClient := agent.GetCloudClient()

		t.Cleanup(func() {
			agent.SetCloudClient(originalClient)
		})

		client := &mockCloudClient{
			attackDetectedEventSent: make(chan struct{}),
		}

		agent.SetCloudClient(client)

		reportDeferredAttack(context.Background())

		select {
		case <-client.attackDetectedEventSent:
			t.Fatal("attack should not be reported")
		case <-time.After(100 * time.Millisecond):
			// Success!
		}
	})

	t.Run("does nothing when no deferred attack exists", func(t *testing.T) {
		originalClient := agent.GetCloudClient()

		t.Cleanup(func() {
			agent.SetCloudClient(originalClient)
		})

		client := &mockCloudClient{
			attackDetectedEventSent: make(chan struct{}),
		}

		agent.SetCloudClient(client)

		ip := "127.0.0.1"
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/test",
			RemoteAddress: &ip,
		})

		reportDeferredAttack(ctx)

		select {
		case <-client.attackDetectedEventSent:
			t.Fatal("attack should not be reported")
		case <-time.After(100 * time.Millisecond):
			// Success!
		}
	})

	t.Run("reports stored attack once", func(t *testing.T) {
		originalClient := agent.GetCloudClient()

		t.Cleanup(func() {
			agent.SetCloudClient(originalClient)
		})

		client := &mockCloudClient{
			attackDetectedEventSent: make(chan struct{}),
		}

		agent.SetCloudClient(client)

		ip := "127.0.0.1"
		req := httptest.NewRequest("GET", "/test", http.NoBody)
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/test",
			RemoteAddress: &ip,
		})

		result := &interceptorResult{
			Kind:          KindPathTraversal,
			Operation:     "filepath.Join",
			Source:        "query",
			PathToPayload: ".path",
			Payload:       "../etc/passwd",
		}

		err := storeDeferredAttack(ctx, result)
		require.NoError(t, err)

		reportDeferredAttack(ctx)
		reportDeferredAttack(ctx)

		select {
		case <-client.attackDetectedEventSent:
		case <-time.After(1 * time.Second):
			t.Fatal("timeout waiting for first attack event")
		}

		select {
		case <-client.attackDetectedEventSent:
			t.Fatal("attack was reported more than once")
		case <-time.After(100 * time.Millisecond):
			// Success! No duplicate
		}
	})
}

func setupOnStoredSSRF(t *testing.T) (*mockCloudClient, func()) {
	t.Helper()
	require.NoError(t, agent.Init(&aikido_types.EnvironmentConfigData{}, &aikido_types.AikidoConfigData{}))

	originalClient := agent.GetCloudClient()
	client := &mockCloudClient{attackDetectedEventSent: make(chan struct{}, 1)}
	agent.SetCloudClient(client)

	return client, func() { agent.SetCloudClient(originalClient) }
}

func TestOnStoredSSRF(t *testing.T) {
	t.Run("returns nil when protection is disabled", func(t *testing.T) {
		originalLoaded := config.IsZenLoaded()
		config.SetZenLoaded(false)
		t.Cleanup(func() { config.SetZenLoaded(originalLoaded) })

		err := OnStoredSSRF(context.Background(), "net/http.Client.Do", "evil.com", "169.254.169.254")
		assert.NoError(t, err)
	})

	for _, blocking := range []bool{false, true} {
		t.Run(fmt.Sprintf("blocking=%v", blocking), func(t *testing.T) {
			_, cleanup := setupOnStoredSSRF(t)
			t.Cleanup(cleanup)

			original := config.IsBlockingEnabled()
			config.SetBlocking(blocking)
			t.Cleanup(func() { config.SetBlocking(original) })

			err := OnStoredSSRF(context.Background(), "net/http.Client.Do", "evil.com", "169.254.169.254")
			if !blocking {
				assert.NoError(t, err)
				return
			}
			var attackErr *AttackDetectedError
			require.ErrorAs(t, err, &attackErr)
			assert.Equal(t, KindStoredSSRF, attackErr.Kind)
			assert.Equal(t, "net/http.Client.Do", attackErr.Operation)
		})
	}

	t.Run("reports attack with hostname and privateIP in metadata", func(t *testing.T) {
		client, cleanup := setupOnStoredSSRF(t)
		t.Cleanup(cleanup)

		original := config.IsBlockingEnabled()
		config.SetBlocking(true)
		t.Cleanup(func() { config.SetBlocking(original) })

		_ = OnStoredSSRF(context.Background(), "net/http.Client.Do", "evil.com", "169.254.169.254")

		select {
		case <-client.attackDetectedEventSent:
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for attack event")
		}

		client.mu.Lock()
		defer client.mu.Unlock()
		assert.Equal(t, string(KindStoredSSRF), client.capturedAttack.Kind)
		assert.Equal(t, "evil.com", client.capturedAttack.Metadata["hostname"])
		assert.Equal(t, "169.254.169.254", client.capturedAttack.Metadata["privateIP"])
		assert.Equal(t, "evil.com", client.capturedAttack.Payload)
	})

	t.Run("works without request context", func(t *testing.T) {
		client, cleanup := setupOnStoredSSRF(t)
		t.Cleanup(cleanup)

		original := config.IsBlockingEnabled()
		config.SetBlocking(true)
		t.Cleanup(func() { config.SetBlocking(original) })

		err := OnStoredSSRF(context.Background(), "net/http.Client.Do", "evil.com", "169.254.169.254")
		require.Error(t, err)

		select {
		case <-client.attackDetectedEventSent:
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for attack event")
		}

		client.mu.Lock()
		defer client.mu.Unlock()
		assert.Empty(t, client.capturedRequest.IPAddress, "request info should be empty without context")
	})

}

type mockCloudClient struct {
	attackDetectedEventSent chan struct{}
	capturedAgentInfo       cloud.AgentInfo
	capturedRequest         aikido_types.RequestInfo
	capturedAttack          aikido_types.AttackDetails
	mu                      sync.Mutex
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
	m.mu.Lock()
	m.capturedAgentInfo = agentInfo
	m.capturedRequest = request
	m.capturedAttack = attack
	m.mu.Unlock()

	m.attackDetectedEventSent <- struct{}{}
}

func (m *mockCloudClient) SendAttackWaveDetectedEvent(agentInfo cloud.AgentInfo, request cloud.AttackWaveRequestInfo, attack cloud.AttackWaveDetails) {
	panic("not implemented")
}
