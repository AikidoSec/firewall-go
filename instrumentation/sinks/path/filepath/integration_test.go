//go:build integration

package filepath_test

import (
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/AikidoSec/firewall-go/instrumentation"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/vulnerabilities"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockCloudClient struct {
	attackDetectedEventSent chan struct{}
	capturedAgentInfo       cloud.AgentInfo
	capturedRequest         aikido_types.RequestInfo
	capturedAttack          aikido_types.AttackDetails
	sendAttackDetectedEvent func(cloud.AgentInfo, aikido_types.RequestInfo, aikido_types.AttackDetails)
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
	if m.sendAttackDetectedEvent != nil {
		m.sendAttackDetectedEvent(agentInfo, request, attack)
	}
}

func (m *mockCloudClient) SendAttackWaveDetectedEvent(agentInfo cloud.AgentInfo, request cloud.AttackWaveRequestInfo, attack cloud.AttackWaveDetails) {
	panic("not implemented")
}

func (m *mockCloudClient) SubscribeToConfigUpdates(ctx context.Context, onUpdate func(int64)) error {
	return nil
}

func newMockClient() *mockCloudClient {
	client := &mockCloudClient{
		attackDetectedEventSent: make(chan struct{}, 10),
	}
	client.sendAttackDetectedEvent = func(agentInfo cloud.AgentInfo, request aikido_types.RequestInfo, attack aikido_types.AttackDetails) {
		client.capturedAgentInfo = agentInfo
		client.capturedRequest = request
		client.capturedAttack = attack
		client.attackDetectedEventSent <- struct{}{}
	}
	return client
}

func TestJoinPathInjectionBlockIsDeferred(t *testing.T) {
	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()

	// Enable blocking so that Zen should cause os.OpenFile to return an error
	original := config.IsBlockingEnabled()
	config.SetBlocking(true)

	t.Cleanup(func() {
		config.SetBlocking(original)
		agent.SetCloudClient(originalClient)
	})

	client := newMockClient()
	agent.SetCloudClient(client)

	req := httptest.NewRequest("GET", "/route?path=../test.txt", http.NoBody)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/route",
		RemoteAddress: &ip,
	})

	request.WrapWithGLS(ctx, func() {
		path := filepath.Join("/tmp/", "../test.txt")
		_, err := os.OpenFile(path, os.O_RDONLY, 0o600)

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
		assert.Equal(t, "filepath.Join", client.capturedAttack.Operation)
		assert.Equal(t, "path/filepath", client.capturedAttack.Module)
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

func TestJoinPathInjectionBareDoubleDotDetected(t *testing.T) {
	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()

	original := config.IsBlockingEnabled()
	config.SetBlocking(true)

	t.Cleanup(func() {
		config.SetBlocking(original)
		agent.SetCloudClient(originalClient)
	})

	client := newMockClient()
	agent.SetCloudClient(client)

	req := httptest.NewRequest("GET", "/route?path=..", http.NoBody)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/route",
		RemoteAddress: &ip,
	})

	request.WrapWithGLS(ctx, func() {
		// ".." as a whole argument must be detected, not just "../" as a substring.
		path := filepath.Join("/var/www/uploads", "..")
		_, err := os.OpenFile(path, os.O_RDONLY, 0o600)

		var detectedErr *vulnerabilities.AttackDetectedError
		require.ErrorAs(t, err, &detectedErr)
	})

	select {
	case <-client.attackDetectedEventSent:
		assert.Equal(t, "path_traversal", client.capturedAttack.Kind)
		assert.True(t, client.capturedAttack.Blocked)
		assert.Equal(t, "..", client.capturedAttack.Payload)
		assert.Equal(t, "filepath.Join", client.capturedAttack.Operation)
		assert.Equal(t, "path/filepath", client.capturedAttack.Module)
		assert.Contains(t, client.capturedAttack.Metadata["filename"], "..")
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for attack event")
	}
}

func TestJoinPathInjectionNotBlockedWhenInMonitoringMode(t *testing.T) {
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

	client := newMockClient()
	agent.SetCloudClient(client)

	req := httptest.NewRequest("GET", "/route?path=../test.txt", http.NoBody)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/route",
		RemoteAddress: &ip,
	})

	request.WrapWithGLS(ctx, func() {
		path := filepath.Join("/tmp/", "../test.txt")
		_, err := os.OpenFile(path, os.O_RDONLY, 0o600)

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
		assert.Equal(t, "filepath.Join", client.capturedAttack.Operation)
		assert.Equal(t, "path/filepath", client.capturedAttack.Module)
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

func TestJoinPathInjectionNoAttackWhenOpenFileNotCalled(t *testing.T) {
	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()

	// Disable blocking
	original := config.IsBlockingEnabled()
	config.SetBlocking(false)

	t.Cleanup(func() {
		config.SetBlocking(original)
		agent.SetCloudClient(originalClient)
	})

	client := newMockClient()
	agent.SetCloudClient(client)

	req := httptest.NewRequest("GET", "/route?path=../test.txt", http.NoBody)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/route",
		RemoteAddress: &ip,
	})

	request.WrapWithGLS(ctx, func() {
		// Call filepath.Join but don't call os.OpenFile
		_ = filepath.Join("/tmp/", "../test.txt")
	})

	select {
	case <-client.attackDetectedEventSent:
		t.Fatal("attack should not be reported when os.OpenFile is not called")
	case <-time.After(100 * time.Millisecond):
		// Success - no attack event should be sent
	}
}

func TestChainedJoinsNoAttackWhenOpenFileNotCalled(t *testing.T) {
	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()

	original := config.IsBlockingEnabled()
	config.SetBlocking(false)

	t.Cleanup(func() {
		config.SetBlocking(original)
		agent.SetCloudClient(originalClient)
	})

	client := newMockClient()
	agent.SetCloudClient(client)

	req := httptest.NewRequest("GET", "/route?path=../test.txt", http.NoBody)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/route",
		RemoteAddress: &ip,
	})

	request.WrapWithGLS(ctx, func() {
		// First join stores a deferred attack
		first := filepath.Join("/tmp/", "../test.txt")
		// Second join should not prematurely report the deferred attack
		_ = filepath.Join(first, "extra")
	})

	select {
	case <-client.attackDetectedEventSent:
		t.Fatal("attack should not be reported when os.OpenFile is not called")
	case <-time.After(100 * time.Millisecond):
		// Success - no attack event should be sent
	}
}

func TestChainedJoinsAttackReportedOnceWhenOpenFileCalled(t *testing.T) {
	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()

	original := config.IsBlockingEnabled()
	config.SetBlocking(false)

	t.Cleanup(func() {
		config.SetBlocking(original)
		agent.SetCloudClient(originalClient)
	})

	attackCount := int64(0)
	client := newMockClient()
	originalSend := client.sendAttackDetectedEvent
	client.sendAttackDetectedEvent = func(agentInfo cloud.AgentInfo, req aikido_types.RequestInfo, attack aikido_types.AttackDetails) {
		atomic.AddInt64(&attackCount, 1)
		originalSend(agentInfo, req, attack)
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
		first := filepath.Join("/tmp/", "../test.txt")
		second := filepath.Join(first, "extra")
		_, _ = os.OpenFile(second, os.O_RDONLY, 0o600)
	})

	select {
	case <-client.attackDetectedEventSent:
		assert.Equal(t, "GET", client.capturedRequest.Method)
		assert.Equal(t, "127.0.0.1", client.capturedRequest.IPAddress)
		assert.Equal(t, "http://example.com/route?path=../test.txt", client.capturedRequest.URL)
		assert.Equal(t, "test", client.capturedRequest.Source)
		assert.Equal(t, "/route", client.capturedRequest.Route)

		assert.Equal(t, "path_traversal", client.capturedAttack.Kind)
		assert.False(t, client.capturedAttack.Blocked)
		assert.Equal(t, "../test.txt", client.capturedAttack.Payload)
		assert.Equal(t, "filepath.Join", client.capturedAttack.Operation)
		assert.Equal(t, "path/filepath", client.capturedAttack.Module)
		assert.Equal(t, ".path", client.capturedAttack.Path)
		assert.Equal(t, map[string]string{"filename": "/tmp/../test.txt"}, client.capturedAttack.Metadata)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for attack event")
	}

	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int64(1), atomic.LoadInt64(&attackCount), "attack should only be reported once")
}

func TestGlobPathInjectionNotBlockedWhenInMonitoringMode(t *testing.T) {
	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()

	original := config.IsBlockingEnabled()
	config.SetBlocking(false)

	t.Cleanup(func() {
		config.SetBlocking(original)
		agent.SetCloudClient(originalClient)
	})

	client := newMockClient()
	agent.SetCloudClient(client)

	req := httptest.NewRequest("GET", "/route?path=../sub", http.NoBody)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/route",
		RemoteAddress: &ip,
	})

	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(sub, 0o755))

	request.WrapWithGLS(ctx, func() {
		target := filepath.Join(sub, "../sub")
		_, _ = filepath.Glob(target + "/*")
	})

	select {
	case <-client.attackDetectedEventSent:
		assert.Equal(t, "path_traversal", client.capturedAttack.Kind)
		assert.False(t, client.capturedAttack.Blocked)
		assert.Equal(t, "../sub", client.capturedAttack.Payload)
		assert.Equal(t, "filepath.Join", client.capturedAttack.Operation)
		assert.Equal(t, "path/filepath", client.capturedAttack.Module)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for attack event")
	}
}

func TestWalkPathInjectionBlockIsDeferred(t *testing.T) {
	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()

	original := config.IsBlockingEnabled()
	config.SetBlocking(true)

	t.Cleanup(func() {
		config.SetBlocking(original)
		agent.SetCloudClient(originalClient)
	})

	client := newMockClient()
	agent.SetCloudClient(client)

	req := httptest.NewRequest("GET", "/route?path=../sub", http.NoBody)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/route",
		RemoteAddress: &ip,
	})

	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(sub, 0o755))

	request.WrapWithGLS(ctx, func() {
		target := filepath.Join(sub, "../sub")

		err := filepath.Walk(target, func(path string, info fs.FileInfo, err error) error {
			return err
		})

		var detectedErr *vulnerabilities.AttackDetectedError
		require.ErrorAs(t, err, &detectedErr)
	})

	select {
	case <-client.attackDetectedEventSent:
		assert.Equal(t, "path_traversal", client.capturedAttack.Kind)
		assert.True(t, client.capturedAttack.Blocked)
		assert.Equal(t, "../sub", client.capturedAttack.Payload)
		assert.Equal(t, "filepath.Join", client.capturedAttack.Operation)
		assert.Equal(t, "path/filepath", client.capturedAttack.Module)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for attack event")
	}
}

func TestWalkPathInjectionNotBlockedWhenInMonitoringMode(t *testing.T) {
	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()

	original := config.IsBlockingEnabled()
	config.SetBlocking(false)

	t.Cleanup(func() {
		config.SetBlocking(original)
		agent.SetCloudClient(originalClient)
	})

	client := newMockClient()
	agent.SetCloudClient(client)

	req := httptest.NewRequest("GET", "/route?path=../sub", http.NoBody)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/route",
		RemoteAddress: &ip,
	})

	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(sub, 0o755))

	request.WrapWithGLS(ctx, func() {
		target := filepath.Join(sub, "../sub")

		err := filepath.Walk(target, func(path string, info fs.FileInfo, err error) error {
			return err
		})
		require.NoError(t, err)
	})

	select {
	case <-client.attackDetectedEventSent:
		assert.Equal(t, "path_traversal", client.capturedAttack.Kind)
		assert.False(t, client.capturedAttack.Blocked)
		assert.Equal(t, "../sub", client.capturedAttack.Payload)
		assert.Equal(t, "filepath.Join", client.capturedAttack.Operation)
		assert.Equal(t, "path/filepath", client.capturedAttack.Module)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for attack event")
	}
}

func TestWalkDirPathInjectionBlockIsDeferred(t *testing.T) {
	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()

	original := config.IsBlockingEnabled()
	config.SetBlocking(true)

	t.Cleanup(func() {
		config.SetBlocking(original)
		agent.SetCloudClient(originalClient)
	})

	client := newMockClient()
	agent.SetCloudClient(client)

	req := httptest.NewRequest("GET", "/route?path=../sub", http.NoBody)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/route",
		RemoteAddress: &ip,
	})

	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(sub, 0o755))

	request.WrapWithGLS(ctx, func() {
		target := filepath.Join(sub, "../sub")

		err := filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
			return err
		})

		var detectedErr *vulnerabilities.AttackDetectedError
		require.ErrorAs(t, err, &detectedErr)
	})

	select {
	case <-client.attackDetectedEventSent:
		assert.Equal(t, "path_traversal", client.capturedAttack.Kind)
		assert.True(t, client.capturedAttack.Blocked)
		assert.Equal(t, "../sub", client.capturedAttack.Payload)
		assert.Equal(t, "filepath.Join", client.capturedAttack.Operation)
		assert.Equal(t, "path/filepath", client.capturedAttack.Module)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for attack event")
	}
}

func TestWalkDirPathInjectionNotBlockedWhenInMonitoringMode(t *testing.T) {
	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()

	original := config.IsBlockingEnabled()
	config.SetBlocking(false)

	t.Cleanup(func() {
		config.SetBlocking(original)
		agent.SetCloudClient(originalClient)
	})

	client := newMockClient()
	agent.SetCloudClient(client)

	req := httptest.NewRequest("GET", "/route?path=../sub", http.NoBody)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/route",
		RemoteAddress: &ip,
	})

	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(sub, 0o755))

	request.WrapWithGLS(ctx, func() {
		target := filepath.Join(sub, "../sub")

		err := filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
			return err
		})
		require.NoError(t, err)
	})

	select {
	case <-client.attackDetectedEventSent:
		assert.Equal(t, "path_traversal", client.capturedAttack.Kind)
		assert.False(t, client.capturedAttack.Blocked)
		assert.Equal(t, "../sub", client.capturedAttack.Payload)
		assert.Equal(t, "filepath.Join", client.capturedAttack.Operation)
		assert.Equal(t, "path/filepath", client.capturedAttack.Module)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for attack event")
	}
}

func TestJoinPathInjectionReportedOnceForMultipleFileOps(t *testing.T) {
	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()

	original := config.IsBlockingEnabled()
	config.SetBlocking(true)

	t.Cleanup(func() {
		config.SetBlocking(original)
		agent.SetCloudClient(originalClient)
	})

	attackCount := int64(0)
	client := newMockClient()
	client.sendAttackDetectedEvent = func(agentInfo cloud.AgentInfo, request aikido_types.RequestInfo, attack aikido_types.AttackDetails) {
		atomic.AddInt64(&attackCount, 1)
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
		path := filepath.Join("/tmp/", "../test.txt")

		// First file operation - should detect and report attack
		_, err := os.OpenFile(path, os.O_RDONLY, 0o600)
		var detectedErr *vulnerabilities.AttackDetectedError
		require.ErrorAs(t, err, &detectedErr)

		// Second file operation - should block but not report again
		_, err = os.ReadFile(path)
		require.ErrorAs(t, err, &detectedErr)
	})

	// Wait for potential attack events
	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, int64(1), atomic.LoadInt64(&attackCount), "attack should only be reported once")
}
