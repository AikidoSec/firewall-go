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

func TestFetchConfigUpdatedAt(t *testing.T) {
	t.Run("successful fetch", func(t *testing.T) {
		updatedAt := time.Now().UnixMilli()
		response := aikido_types.CloudConfigUpdatedAt{
			ServiceID:       123,
			ConfigUpdatedAt: updatedAt,
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, configUpdatedAtAPIRoute, r.URL.Path)
			assert.Equal(t, "test-token", r.Header.Get("Authorization"))
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client := NewClient(&ClientConfig{
			RealtimeEndpoint: server.URL,
			Token:            "test-token",
		})

		result := client.FetchConfigUpdatedAt()

		expected := time.UnixMilli(updatedAt)
		assert.Equal(t, expected, result)
	})

	t.Run("network error returns zero time", func(t *testing.T) {
		client := NewClient(&ClientConfig{
			RealtimeEndpoint: "http://localhost:1", // Invalid endpoint
			Token:            "test-token",
		})

		result := client.FetchConfigUpdatedAt()

		assert.True(t, result.IsZero())
	})

	t.Run("invalid JSON returns zero time", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{invalid json}`))
		}))
		defer server.Close()

		client := NewClient(&ClientConfig{
			RealtimeEndpoint: server.URL,
			Token:            "test-token",
		})

		result := client.FetchConfigUpdatedAt()

		assert.True(t, result.IsZero())
	})

	t.Run("non-200 status returns zero time", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := NewClient(&ClientConfig{
			RealtimeEndpoint: server.URL,
			Token:            "test-token",
		})

		result := client.FetchConfigUpdatedAt()

		assert.True(t, result.IsZero())
	})

	t.Run("no token set returns zero time", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("should not make request without token")
		}))
		defer server.Close()

		client := NewClient(&ClientConfig{
			RealtimeEndpoint: server.URL,
			Token:            "",
		})

		result := client.FetchConfigUpdatedAt()

		assert.True(t, result.IsZero())
	})
}

func TestFetchConfig(t *testing.T) {
	t.Run("successful fetch", func(t *testing.T) {
		blockTrue := true
		expectedConfig := &aikido_types.CloudConfigData{
			Success:               true,
			ServiceID:             456,
			ConfigUpdatedAt:       time.Now().UnixMilli(),
			HeartbeatIntervalInMS: 300000,
			Endpoints: []aikido_types.Endpoint{
				{
					Method:             "POST",
					Route:              "/api/users",
					ForceProtectionOff: false,
					RateLimiting: aikido_types.RateLimiting{
						Enabled:        true,
						MaxRequests:    100,
						WindowSizeInMS: 60000,
					},
				},
			},
			BlockedUserIds:           []string{"user1", "user2"},
			BypassedIPs:              []string{"192.168.1.1"},
			ReceivedAnyStats:         true,
			Block:                    &blockTrue,
			BlockNewOutgoingRequests: true,
			Domains: []aikido_types.OutboundDomains{
				{Hostname: "malicious.com", Mode: "block"},
				{Hostname: "allowed.com", Mode: "allow"},
			},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, configAPIRoute, r.URL.Path)
			assert.Equal(t, "test-token", r.Header.Get("Authorization"))

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(expectedConfig)
		}))
		defer server.Close()

		client := NewClient(&ClientConfig{
			APIEndpoint: server.URL,
			Token:       "test-token",
		})

		result, err := client.FetchConfig()

		require.NoError(t, err)
		assert.Equal(t, expectedConfig.ServiceID, result.ServiceID)
		assert.Equal(t, expectedConfig.HeartbeatIntervalInMS, result.HeartbeatIntervalInMS)
		assert.Equal(t, expectedConfig.ReceivedAnyStats, result.ReceivedAnyStats)
		assert.Len(t, result.Endpoints, 1)
		assert.Equal(t, "POST", result.Endpoints[0].Method)
		assert.Equal(t, "/api/users", result.Endpoints[0].Route)
		assert.True(t, result.BlockNewOutgoingRequests)
		assert.Len(t, result.Domains, 2)
		assert.Equal(t, "malicious.com", result.Domains[0].Hostname)
		assert.Equal(t, "block", result.Domains[0].Mode)
		assert.Equal(t, "allowed.com", result.Domains[1].Hostname)
		assert.Equal(t, "allow", result.Domains[1].Mode)
	})

	t.Run("network error", func(t *testing.T) {
		client := NewClient(&ClientConfig{
			APIEndpoint: "http://localhost:1",
			Token:       "test-token",
		})

		result, err := client.FetchConfig()

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("invalid JSON returns parsing error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{invalid json}`))
		}))
		defer server.Close()

		client := NewClient(&ClientConfig{
			APIEndpoint: server.URL,
			Token:       "test-token",
		})

		result, err := client.FetchConfig()

		assert.ErrorIs(t, err, ErrParsingConfig)
		assert.Nil(t, result)
	})

	t.Run("non-200 status returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		client := NewClient(&ClientConfig{
			APIEndpoint: server.URL,
			Token:       "test-token",
		})

		result, err := client.FetchConfig()

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("no token set returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("should not make request without token")
		}))
		defer server.Close()

		client := NewClient(&ClientConfig{
			APIEndpoint: server.URL,
			Token:       "",
		})

		result, err := client.FetchConfig()

		assert.ErrorIs(t, err, ErrNoTokenSet)
		assert.Nil(t, result)
	})
}

func TestParseCloudConfigResponse(t *testing.T) {
	t.Run("valid JSON with all fields", func(t *testing.T) {
		blockFalse := false
		input := &aikido_types.CloudConfigData{
			Success:               true,
			ServiceID:             789,
			ConfigUpdatedAt:       time.Now().UnixMilli(),
			HeartbeatIntervalInMS: 120000,
			Endpoints: []aikido_types.Endpoint{
				{
					Method: "GET",
					Route:  "/api/health",
					RateLimiting: aikido_types.RateLimiting{
						Enabled:        false,
						MaxRequests:    0,
						WindowSizeInMS: 0,
					},
				},
			},
			BlockedUserIds:   []string{},
			BypassedIPs:      []string{},
			ReceivedAnyStats: false,
			Block:            &blockFalse,
		}
		jsonBytes, _ := json.Marshal(input)

		result, err := parseCloudConfigResponse(jsonBytes)

		require.NoError(t, err)
		assert.Equal(t, input.ServiceID, result.ServiceID)
		assert.Equal(t, input.HeartbeatIntervalInMS, result.HeartbeatIntervalInMS)
		assert.False(t, result.ReceivedAnyStats)
		assert.NotNil(t, result.Block)
		assert.False(t, *result.Block)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		invalidJSON := []byte(`{"invalid": json}`)

		result, err := parseCloudConfigResponse(invalidJSON)

		assert.ErrorIs(t, err, ErrParsingConfig)
		assert.Nil(t, result)
	})

	t.Run("empty JSON object", func(t *testing.T) {
		emptyJSON := []byte(`{}`)

		result, err := parseCloudConfigResponse(emptyJSON)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, 0, result.ServiceID)
		assert.False(t, result.Success)
	})

	t.Run("minimal valid config", func(t *testing.T) {
		minimalJSON := []byte(`{
			"success": true,
			"serviceId": 100,
			"configUpdatedAt": 1234567890,
			"heartbeatIntervalInMS": 60000,
			"endpoints": [],
			"blockedUserIds": [],
			"allowedIPAddresses": [],
			"receivedAnyStats": false
		}`)

		result, err := parseCloudConfigResponse(minimalJSON)

		require.NoError(t, err)
		assert.True(t, result.Success)
		assert.Equal(t, 100, result.ServiceID)
		assert.Equal(t, int64(1234567890), result.ConfigUpdatedAt)
		assert.Len(t, result.Endpoints, 0)
	})

	t.Run("parse config with domains and BlockNewOutgoingRequests", func(t *testing.T) {
		configJSON := []byte(`{
			"success": true,
			"serviceId": 200,
			"configUpdatedAt": 1234567890,
			"heartbeatIntervalInMS": 60000,
			"endpoints": [],
			"blockedUserIds": [],
			"allowedIPAddresses": [],
			"receivedAnyStats": false,
			"blockNewOutgoingRequests": true,
			"domains": [
				{"hostname": "blocked.example.com", "mode": "block"},
				{"hostname": "allowed.example.com", "mode": "allow"}
			]
		}`)

		result, err := parseCloudConfigResponse(configJSON)

		require.NoError(t, err)
		assert.True(t, result.Success)
		assert.Equal(t, 200, result.ServiceID)
		assert.True(t, result.BlockNewOutgoingRequests)
		assert.Len(t, result.Domains, 2)
		assert.Equal(t, "blocked.example.com", result.Domains[0].Hostname)
		assert.Equal(t, "block", result.Domains[0].Mode)
		assert.Equal(t, "allowed.example.com", result.Domains[1].Hostname)
		assert.Equal(t, "allow", result.Domains[1].Mode)
	})
}

func TestFetchListsConfig(t *testing.T) {
	t.Run("successful fetch", func(t *testing.T) {
		expectedLists := &aikido_types.ListsConfigData{
			Success:   true,
			ServiceID: 999,
			BlockedIPAddresses: []aikido_types.IPList{
				{
					Source:      "threat-intel",
					Description: "Known malicious IPs",
					IPs:         []string{"10.0.0.1", "10.0.0.2"},
				},
			},
			AllowedIPAddresses: []aikido_types.IPList{
				{
					Source:      "geo-allowed",
					Description: "Allowed countries",
					IPs:         []string{"8.8.8.0/24", "1.1.1.1"},
				},
			},
			BlockedUserAgents: "BadBot|EvilCrawler",
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, listsAPIRoute, r.URL.Path)
			assert.Equal(t, "test-token", r.Header.Get("Authorization"))

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(expectedLists)
		}))
		defer server.Close()

		client := NewClient(&ClientConfig{
			APIEndpoint: server.URL,
			Token:       "test-token",
		})

		result, err := client.FetchListsConfig()

		require.NoError(t, err)
		assert.Equal(t, expectedLists.ServiceID, result.ServiceID)
		assert.Len(t, result.BlockedIPAddresses, 1)
		assert.Equal(t, "threat-intel", result.BlockedIPAddresses[0].Source)
		assert.Len(t, result.AllowedIPAddresses, 1)
		assert.Equal(t, "geo-allowed", result.AllowedIPAddresses[0].Source)
		assert.Equal(t, "Allowed countries", result.AllowedIPAddresses[0].Description)
		assert.Equal(t, []string{"8.8.8.0/24", "1.1.1.1"}, result.AllowedIPAddresses[0].IPs)
		assert.Equal(t, "BadBot|EvilCrawler", result.BlockedUserAgents)
	})

	t.Run("network error", func(t *testing.T) {
		client := NewClient(&ClientConfig{
			APIEndpoint: "http://localhost:1",
			Token:       "test-token",
		})

		result, err := client.FetchListsConfig()

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{not valid json}`))
		}))
		defer server.Close()

		client := NewClient(&ClientConfig{
			APIEndpoint: server.URL,
			Token:       "test-token",
		})

		result, err := client.FetchListsConfig()

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("non-200 status returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer server.Close()

		client := NewClient(&ClientConfig{
			APIEndpoint: server.URL,
			Token:       "test-token",
		})

		result, err := client.FetchListsConfig()

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("empty lists config", func(t *testing.T) {
		emptyLists := &aikido_types.ListsConfigData{
			Success:            true,
			ServiceID:          111,
			BlockedIPAddresses: []aikido_types.IPList{},
			AllowedIPAddresses: []aikido_types.IPList{},
			BlockedUserAgents:  "",
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(emptyLists)
		}))
		defer server.Close()

		client := NewClient(&ClientConfig{
			APIEndpoint: server.URL,
			Token:       "test-token",
		})

		result, err := client.FetchListsConfig()

		require.NoError(t, err)
		assert.True(t, result.Success)
		assert.Len(t, result.BlockedIPAddresses, 0)
		assert.Len(t, result.AllowedIPAddresses, 0)
		assert.Empty(t, result.BlockedUserAgents)
	})
}
