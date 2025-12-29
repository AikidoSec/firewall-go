//go:build integration

package os_test

import (
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockCloudClient struct {
	attackDetectedEventSent chan struct{}
	capturedAgentInfo       cloud.AgentInfo
	capturedRequest         aikido_types.RequestInfo
	capturedAttack          aikido_types.AttackDetails
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
	m.capturedAgentInfo = agentInfo
	m.capturedRequest = request
	m.capturedAttack = attack
	m.attackDetectedEventSent <- struct{}{}
}

func TestOpenFileIsAutomaticallyInstrumented(t *testing.T) {
	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()

	// Enable blocking so that Zen should cause os.OpenFile to return an error
	original := config.IsBlockingEnabled()
	config.SetBlocking(true)

	t.Cleanup(func() {
		config.SetBlocking(original)
		agent.SetCloudClient(originalClient)
	})

	client := &mockCloudClient{
		attackDetectedEventSent: make(chan struct{}),
	}
	agent.SetCloudClient(client)

	req := httptest.NewRequest("GET", "/route?path=../test.txt", http.NoBody)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/route",
		RemoteAddress: &ip,
	})

	request.WrapWithGLS(ctx, func() {
		_, err := os.OpenFile("/tmp/"+"../test.txt", os.O_RDONLY, 0o600)

		var detectedErr *vulnerabilities.AttackDetectedError
		require.ErrorAs(t, err, &detectedErr)
	})

	select {
	case <-client.attackDetectedEventSent:
		// Success
		assert.Equal(t, "GET", client.capturedRequest.Method)
		assert.Equal(t, "127.0.0.1", client.capturedRequest.IPAddress)
		assert.Equal(t, "unknown", client.capturedRequest.UserAgent)
		assert.Equal(t, "http://example.com/route?path=../test.txt", client.capturedRequest.URL)
		assert.Equal(t, "test", client.capturedRequest.Source)
		assert.Equal(t, "/route", client.capturedRequest.Route)

		assert.Equal(t, "path_traversal", client.capturedAttack.Kind)
		assert.True(t, client.capturedAttack.Blocked)
		assert.Equal(t, "../test.txt", client.capturedAttack.Payload)
		assert.Equal(t, "os.OpenFile", client.capturedAttack.Operation)
		assert.Equal(t, "Module", client.capturedAttack.Module)
		assert.Equal(t, ".path", client.capturedAttack.Path)
		assert.Equal(t, "../test.txt", client.capturedAttack.Payload)
		assert.Equal(t, map[string]string{
			"filename": "/tmp/../test.txt",
		}, client.capturedAttack.Metadata)
		assert.Nil(t, nil, client.capturedAttack.User)

		assert.NotEmpty(t, client.capturedAgentInfo)

	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for attack event")
	}
}

func TestOpenFileIsNotBlockedWhenInMonitoringMode(t *testing.T) {
	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()

	// Disable blocking so that Zen should allow the method to continue
	// But we should see that an attack has been reported to the API
	original := config.IsBlockingEnabled()
	config.SetBlocking(false)

	t.Cleanup(func() {
		config.SetBlocking(original)
		agent.SetCloudClient(originalClient)
	})

	client := &mockCloudClient{
		attackDetectedEventSent: make(chan struct{}),
	}
	agent.SetCloudClient(client)

	req := httptest.NewRequest("GET", "/route?path=../test.txt", http.NoBody)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/route",
		RemoteAddress: &ip,
	})

	request.WrapWithGLS(ctx, func() {
		_, err := os.OpenFile("/tmp/"+"../test.txt", os.O_RDONLY, 0o600)

		var notFound *fs.PathError
		require.ErrorAs(t, err, &notFound)
	})

	select {
	case <-client.attackDetectedEventSent:
		// Success
		assert.Equal(t, "GET", client.capturedRequest.Method)
		assert.Equal(t, "127.0.0.1", client.capturedRequest.IPAddress)
		assert.Equal(t, "unknown", client.capturedRequest.UserAgent)
		assert.Equal(t, "http://example.com/route?path=../test.txt", client.capturedRequest.URL)
		assert.Equal(t, "test", client.capturedRequest.Source)
		assert.Equal(t, "/route", client.capturedRequest.Route)

		assert.Equal(t, "path_traversal", client.capturedAttack.Kind)
		assert.False(t, client.capturedAttack.Blocked)
		assert.Equal(t, "../test.txt", client.capturedAttack.Payload)
		assert.Equal(t, "os.OpenFile", client.capturedAttack.Operation)
		assert.Equal(t, "Module", client.capturedAttack.Module)
		assert.Equal(t, ".path", client.capturedAttack.Path)
		assert.Equal(t, "../test.txt", client.capturedAttack.Payload)
		assert.Equal(t, map[string]string{
			"filename": "/tmp/../test.txt",
		}, client.capturedAttack.Metadata)
		assert.Nil(t, nil, client.capturedAttack.User)

		assert.NotEmpty(t, client.capturedAgentInfo)

	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for attack event")
	}
}
