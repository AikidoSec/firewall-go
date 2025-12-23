package testutil

import (
	"sync"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
)

// MockCloudClient is a mock implementation of agent.CloudClient for testing.
// It captures attack detection events and allows tests to verify whether attacks were detected.
type MockCloudClient struct {
	AttackDetectedEventSent chan struct{}
	CapturedAgentInfo       cloud.AgentInfo
	CapturedRequest         aikido_types.RequestInfo
	CapturedAttack          aikido_types.AttackDetails
	mu                      sync.Mutex
}

func NewMockCloudClient() *MockCloudClient {
	return &MockCloudClient{
		AttackDetectedEventSent: make(chan struct{}, 10),
	}
}

func (m *MockCloudClient) SendStartEvent(agentInfo cloud.AgentInfo) (*aikido_types.CloudConfigData, error) {
	return nil, nil
}

func (m *MockCloudClient) SendHeartbeatEvent(agentInfo cloud.AgentInfo, data cloud.HeartbeatData) (*aikido_types.CloudConfigData, error) {
	return nil, nil
}

func (m *MockCloudClient) FetchConfigUpdatedAt() time.Time {
	return time.Time{}
}

func (m *MockCloudClient) FetchConfig() (*aikido_types.CloudConfigData, error) {
	return nil, nil
}

func (m *MockCloudClient) FetchListsConfig() (*aikido_types.ListsConfigData, error) {
	return nil, nil
}

func (m *MockCloudClient) SendAttackDetectedEvent(agentInfo cloud.AgentInfo, request aikido_types.RequestInfo, attack aikido_types.AttackDetails) {
	m.mu.Lock()
	m.CapturedAgentInfo = agentInfo
	m.CapturedRequest = request
	m.CapturedAttack = attack
	m.mu.Unlock()

	m.AttackDetectedEventSent <- struct{}{}
}
