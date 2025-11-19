package cloud

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSendStartEvent(t *testing.T) {
	t.Run("successful send", func(t *testing.T) {
		agentInfo := AgentInfo{
			DryMode:   true,
			Hostname:  "prod-server",
			Version:   "2.5.1",
			IPAddress: "10.0.0.50",
			OS: OSInfo{
				Name:    "darwin",
				Version: "13.0",
			},
			Platform: PlatformInfo{
				Name:    "go",
				Version: "1.22.0",
			},
			Packages: map[string]string{
				"github.com/gorilla/mux": "v1.8.0",
				"go.uber.org/zap":        "v1.24.0",
			},
			PreventPrototypePollution: true,
			NodeEnv:                   "staging",
			Library:                   "firewall-go",
		}

		blockTrue := true
		expectedConfig := &aikido_types.CloudConfigData{
			Success:               true,
			ServiceID:             123,
			ConfigUpdatedAt:       time.Now().UnixMilli(),
			HeartbeatIntervalInMS: 300000,
			Endpoints:             []aikido_types.Endpoint{},
			BlockedUserIds:        []string{},
			BypassedIPs:           []string{},
			ReceivedAnyStats:      false,
			Block:                 &blockTrue,
		}

		var receivedEvent StartEvent
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, eventsAPIMethod, r.Method)
			assert.Equal(t, eventsAPIRoute, r.URL.Path)
			assert.Equal(t, "test-token", r.Header.Get("Authorization"))
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			// Decode and validate the request body
			err := json.NewDecoder(r.Body).Decode(&receivedEvent)
			require.NoError(t, err)

			// Validate all event fields
			assert.Equal(t, "started", receivedEvent.Type)
			assert.Equal(t, true, receivedEvent.Agent.DryMode)
			assert.Equal(t, "prod-server", receivedEvent.Agent.Hostname)
			assert.Equal(t, "2.5.1", receivedEvent.Agent.Version)
			assert.Equal(t, "10.0.0.50", receivedEvent.Agent.IPAddress)
			assert.Equal(t, "darwin", receivedEvent.Agent.OS.Name)
			assert.Equal(t, "13.0", receivedEvent.Agent.OS.Version)
			assert.Equal(t, "go", receivedEvent.Agent.Platform.Name)
			assert.Equal(t, "1.22.0", receivedEvent.Agent.Platform.Version)
			assert.Len(t, receivedEvent.Agent.Packages, 2)
			assert.Equal(t, "v1.8.0", receivedEvent.Agent.Packages["github.com/gorilla/mux"])
			assert.Equal(t, "v1.24.0", receivedEvent.Agent.Packages["go.uber.org/zap"])
			assert.True(t, receivedEvent.Agent.PreventPrototypePollution)
			assert.Equal(t, "staging", receivedEvent.Agent.NodeEnv)
			assert.Equal(t, "firewall-go", receivedEvent.Agent.Library)
			assert.Greater(t, receivedEvent.Time, int64(0))

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(expectedConfig)
		}))
		defer server.Close()

		client := NewClient(&ClientConfig{
			APIEndpoint: server.URL,
			Token:       "test-token",
		})

		result, err := client.SendStartEvent(agentInfo)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, expectedConfig.ServiceID, result.ServiceID)
		assert.Equal(t, expectedConfig.HeartbeatIntervalInMS, result.HeartbeatIntervalInMS)
	})

	t.Run("network error", func(t *testing.T) {
		agentInfo := AgentInfo{
			Hostname:  "test-host",
			Version:   "1.0.0",
			IPAddress: "192.168.1.100",
		}

		client := NewClient(&ClientConfig{
			APIEndpoint: "http://localhost:1",
			Token:       "test-token",
		})

		result, err := client.SendStartEvent(agentInfo)

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("invalid response JSON", func(t *testing.T) {
		agentInfo := AgentInfo{
			Hostname: "test-host",
			Version:  "1.0.0",
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{invalid json}`))
		}))
		defer server.Close()

		client := NewClient(&ClientConfig{
			APIEndpoint: server.URL,
			Token:       "test-token",
		})

		result, err := client.SendStartEvent(agentInfo)

		assert.ErrorIs(t, err, ErrParsingConfig)
		assert.Nil(t, result)
	})

	t.Run("non-200 status returns error", func(t *testing.T) {
		agentInfo := AgentInfo{
			Hostname: "test-host",
			Version:  "1.0.0",
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		client := NewClient(&ClientConfig{
			APIEndpoint: server.URL,
			Token:       "test-token",
		})

		result, err := client.SendStartEvent(agentInfo)

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("no token set returns error", func(t *testing.T) {
		agentInfo := AgentInfo{
			Hostname: "test-host",
			Version:  "1.0.0",
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("should not make request without token")
		}))
		defer server.Close()

		client := NewClient(&ClientConfig{
			APIEndpoint: server.URL,
			Token:       "",
		})

		result, err := client.SendStartEvent(agentInfo)

		assert.ErrorIs(t, err, ErrNoTokenSet)
		assert.Nil(t, result)
	})
}
