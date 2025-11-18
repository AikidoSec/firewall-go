package config

import (
	"sync"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestGlobals initialises globals for testing
func setupTestGlobals() {
	globals.EnvironmentConfig = &aikido_types.EnvironmentConfigData{
		PlatformName:     "go",
		PlatformVersion:  "1.21.0",
		Endpoint:         "https://test.aikido.dev",
		RealtimeEndpoint: "https://test-runtime.aikido.dev",
		Library:          "firewall-go",
		Version:          "1.0.0",
	}

	globals.AikidoConfig = &aikido_types.AikidoConfigData{
		Token:                     "test-token",
		LogLevel:                  "INFO",
		Blocking:                  false,
		LocalhostAllowedByDefault: true,
		CollectAPISchema:          true,
	}
}

// resetServiceConfig clears the service config for test isolation
func resetServiceConfig() {
	serviceConfigMutex.Lock()
	defer serviceConfigMutex.Unlock()
	serviceConfig = ServiceConfigData{}
}

func TestUpdateServiceConfig(t *testing.T) {
	setupTestGlobals()
	defer resetServiceConfig()

	t.Run("updates config with all fields", func(t *testing.T) {
		resetServiceConfig()

		blockTrue := true
		now := time.Now().UnixMilli()
		cloudConfig := &aikido_types.CloudConfigData{
			Success:               true,
			ServiceID:             123,
			ConfigUpdatedAt:       now,
			HeartbeatIntervalInMS: 300000,
			Endpoints: []aikido_types.Endpoint{
				{
					Method: "POST",
					Route:  "/api/users",
					RateLimiting: aikido_types.RateLimiting{
						Enabled:        true,
						MaxRequests:    100,
						WindowSizeInMS: 60000,
					},
					ForceProtectionOff: false,
					AllowedIPAddresses: []string{"192.168.1.1"},
				},
			},
			BlockedUserIds:   []string{"user1", "user2"},
			BypassedIPs:      []string{"10.0.0.1"},
			ReceivedAnyStats: true,
			Block:            &blockTrue,
		}

		listsConfig := &aikido_types.ListsConfigData{
			Success:   true,
			ServiceID: 123,
			BlockedIPAddresses: []aikido_types.BlockedIPsData{
				{
					Source:      "threat-intel",
					Description: "Known malicious IPs",
					IPs:         []string{"203.0.113.0", "203.0.113.1"},
				},
			},
			BlockedUserAgents: "BadBot|EvilCrawler",
		}

		UpdateServiceConfig(cloudConfig, listsConfig)

		// Verify config was updated
		updatedAt := GetCloudConfigUpdatedAt()
		assert.Equal(t, now, updatedAt)

		// Verify endpoints
		endpoints := GetEndpoints()
		assert.Len(t, endpoints, 1)
		assert.Equal(t, "POST", endpoints[0].Method)
		assert.Equal(t, "/api/users", endpoints[0].Route)
		assert.True(t, endpoints[0].RateLimiting.Enabled)

		// Verify blocked users
		assert.True(t, IsUserBlocked("user1"))
		assert.True(t, IsUserBlocked("user2"))
		assert.False(t, IsUserBlocked("user3"))

		// Verify bypassed IPs
		assert.True(t, IsIPBypassed("10.0.0.1"))
		assert.False(t, IsIPBypassed("10.0.0.2"))

		// Verify blocked IPs
		blocked, desc := IsIPBlocked("203.0.113.0")
		assert.True(t, blocked)
		assert.Equal(t, "Known malicious IPs", desc)

		// Verify blocked user agents
		blocked, reason := IsUserAgentBlocked("BadBot/1.0")
		assert.True(t, blocked)
		assert.Equal(t, "bot detection", reason)
	})

	t.Run("handles nil cloud config", func(t *testing.T) {
		resetServiceConfig()

		UpdateServiceConfig(nil, nil)

		// Config should remain empty
		updatedAt := GetCloudConfigUpdatedAt()
		assert.Equal(t, int64(0), updatedAt)
	})

	t.Run("uses aikido config blocking when cloud config block is nil", func(t *testing.T) {
		resetServiceConfig()
		globals.AikidoConfig.Blocking = true

		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
			Block:           nil, // nil means use local config
		}

		UpdateServiceConfig(cloudConfig, nil)

		serviceConfigMutex.RLock()
		assert.True(t, serviceConfig.Block)
		serviceConfigMutex.RUnlock()

		globals.AikidoConfig.Blocking = false
	})

	t.Run("overrides aikido config blocking when cloud config block is set", func(t *testing.T) {
		resetServiceConfig()
		globals.AikidoConfig.Blocking = true

		blockFalse := false
		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
			Block:           &blockFalse,
		}

		UpdateServiceConfig(cloudConfig, nil)

		serviceConfigMutex.RLock()
		assert.False(t, serviceConfig.Block)
		serviceConfigMutex.RUnlock()

		globals.AikidoConfig.Blocking = false
	})

	t.Run("handles empty lists config", func(t *testing.T) {
		resetServiceConfig()

		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}

		UpdateServiceConfig(cloudConfig, nil)

		// Should not panic and should have empty blocked IPs
		serviceConfigMutex.RLock()
		assert.Nil(t, serviceConfig.BlockedIPs)
		assert.Nil(t, serviceConfig.BlockedUserAgents)
		serviceConfigMutex.RUnlock()
	})
}

func TestIsIPBlocked(t *testing.T) {
	setupTestGlobals()
	defer resetServiceConfig()

	t.Run("blocks IPv4 address in blocklist", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			BlockedIPAddresses: []aikido_types.BlockedIPsData{
				{
					Source:      "manual",
					Description: "Manually blocked",
					IPs:         []string{"192.168.1.100", "10.0.0.0/24"},
				},
			},
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		blocked, desc := IsIPBlocked("192.168.1.100")
		assert.True(t, blocked)
		assert.Equal(t, "Manually blocked", desc)

		// Test CIDR range
		blocked, desc = IsIPBlocked("10.0.0.50")
		assert.True(t, blocked)
		assert.Equal(t, "Manually blocked", desc)
	})

	t.Run("blocks IPv6 address in blocklist", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			BlockedIPAddresses: []aikido_types.BlockedIPsData{
				{
					Source:      "ipv6-test",
					Description: "IPv6 blocklist",
					IPs:         []string{"2001:db8::1", "2001:db8::/32"},
				},
			},
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		blocked, desc := IsIPBlocked("2001:db8::1")
		assert.True(t, blocked)
		assert.Equal(t, "IPv6 blocklist", desc)

		// Test IPv6 CIDR range
		blocked, desc = IsIPBlocked("2001:db8::100")
		assert.True(t, blocked)
		assert.Equal(t, "IPv6 blocklist", desc)
	})

	t.Run("does not block IP not in blocklist", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			BlockedIPAddresses: []aikido_types.BlockedIPsData{
				{
					Source:      "test",
					Description: "Test blocklist",
					IPs:         []string{"192.168.1.100"},
				},
			},
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		blocked, desc := IsIPBlocked("192.168.1.200")
		assert.False(t, blocked)
		assert.Empty(t, desc)
	})

	t.Run("handles invalid IP address", func(t *testing.T) {
		resetServiceConfig()

		blocked, desc := IsIPBlocked("not-an-ip")
		assert.False(t, blocked)
		assert.Empty(t, desc)
	})

	t.Run("handles empty blocklist", func(t *testing.T) {
		resetServiceConfig()

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, nil)

		blocked, desc := IsIPBlocked("192.168.1.1")
		assert.False(t, blocked)
		assert.Empty(t, desc)
	})

	t.Run("checks multiple blocklists", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			BlockedIPAddresses: []aikido_types.BlockedIPsData{
				{
					Source:      "list1",
					Description: "First list",
					IPs:         []string{"10.0.0.1"},
				},
				{
					Source:      "list2",
					Description: "Second list",
					IPs:         []string{"10.0.0.2"},
				},
			},
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		blocked, desc := IsIPBlocked("10.0.0.1")
		assert.True(t, blocked)
		assert.Equal(t, "First list", desc)

		blocked, desc = IsIPBlocked("10.0.0.2")
		assert.True(t, blocked)
		assert.Equal(t, "Second list", desc)
	})
}

func TestIsUserAgentBlocked(t *testing.T) {
	setupTestGlobals()
	defer resetServiceConfig()

	t.Run("blocks matching user agent", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			BlockedUserAgents: "BadBot|EvilCrawler|Scraper",
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		blocked, reason := IsUserAgentBlocked("BadBot/1.0")
		assert.True(t, blocked)
		assert.Equal(t, "bot detection", reason)

		blocked, reason = IsUserAgentBlocked("Mozilla/5.0 EvilCrawler")
		assert.True(t, blocked)
		assert.Equal(t, "bot detection", reason)
	})

	t.Run("case insensitive matching", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			BlockedUserAgents: "badbot",
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		blocked, _ := IsUserAgentBlocked("BADBOT/1.0")
		assert.True(t, blocked)

		blocked, _ = IsUserAgentBlocked("BadBot/1.0")
		assert.True(t, blocked)

		blocked, _ = IsUserAgentBlocked("badbot/1.0")
		assert.True(t, blocked)
	})

	t.Run("does not block non-matching user agent", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			BlockedUserAgents: "BadBot",
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		blocked, reason := IsUserAgentBlocked("Mozilla/5.0 Chrome/91.0")
		assert.False(t, blocked)
		assert.Empty(t, reason)
	})

	t.Run("handles empty blocked user agents", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			BlockedUserAgents: "",
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		blocked, reason := IsUserAgentBlocked("AnyBot/1.0")
		assert.False(t, blocked)
		assert.Empty(t, reason)
	})

	t.Run("handles nil blocked user agents regex", func(t *testing.T) {
		resetServiceConfig()

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, nil)

		blocked, reason := IsUserAgentBlocked("AnyBot/1.0")
		assert.False(t, blocked)
		assert.Empty(t, reason)
	})
}

func TestIsUserBlocked(t *testing.T) {
	setupTestGlobals()
	defer resetServiceConfig()

	t.Run("blocks user in blocklist", func(t *testing.T) {
		resetServiceConfig()

		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
			BlockedUserIds:  []string{"user123", "user456"},
		}

		UpdateServiceConfig(cloudConfig, nil)

		assert.True(t, IsUserBlocked("user123"))
		assert.True(t, IsUserBlocked("user456"))
	})

	t.Run("does not block user not in blocklist", func(t *testing.T) {
		resetServiceConfig()

		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
			BlockedUserIds:  []string{"user123"},
		}

		UpdateServiceConfig(cloudConfig, nil)

		assert.False(t, IsUserBlocked("user789"))
	})

	t.Run("handles empty blocklist", func(t *testing.T) {
		resetServiceConfig()

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, nil)

		assert.False(t, IsUserBlocked("anyuser"))
	})
}

func TestSetUserBlocked(t *testing.T) {
	setupTestGlobals()
	defer resetServiceConfig()

	t.Run("adds user to blocklist", func(t *testing.T) {
		resetServiceConfig()

		assert.False(t, IsUserBlocked("newuser"))

		SetUserBlocked("newuser")

		assert.True(t, IsUserBlocked("newuser"))
	})

	t.Run("can add multiple users", func(t *testing.T) {
		resetServiceConfig()

		SetUserBlocked("user1")
		SetUserBlocked("user2")
		SetUserBlocked("user3")

		assert.True(t, IsUserBlocked("user1"))
		assert.True(t, IsUserBlocked("user2"))
		assert.True(t, IsUserBlocked("user3"))
	})

	t.Run("initializes map if nil", func(t *testing.T) {
		resetServiceConfig()

		// Ensure map is nil
		serviceConfigMutex.Lock()
		serviceConfig.BlockedUserIDs = nil
		serviceConfigMutex.Unlock()

		SetUserBlocked("testuser")

		assert.True(t, IsUserBlocked("testuser"))
	})

	t.Run("is idempotent", func(t *testing.T) {
		resetServiceConfig()

		SetUserBlocked("sameuser")
		SetUserBlocked("sameuser")
		SetUserBlocked("sameuser")

		assert.True(t, IsUserBlocked("sameuser"))
	})
}

func TestIsIPBypassed(t *testing.T) {
	setupTestGlobals()
	defer resetServiceConfig()

	t.Run("bypasses IP in bypass list", func(t *testing.T) {
		resetServiceConfig()

		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
			BypassedIPs:     []string{"127.0.0.1", "192.168.1.100"},
		}

		UpdateServiceConfig(cloudConfig, nil)

		assert.True(t, IsIPBypassed("127.0.0.1"))
		assert.True(t, IsIPBypassed("192.168.1.100"))
	})

	t.Run("does not bypass IP not in list", func(t *testing.T) {
		resetServiceConfig()

		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
			BypassedIPs:     []string{"127.0.0.1"},
		}

		UpdateServiceConfig(cloudConfig, nil)

		assert.False(t, IsIPBypassed("192.168.1.1"))
	})

	t.Run("handles empty bypass list", func(t *testing.T) {
		resetServiceConfig()

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, nil)

		assert.False(t, IsIPBypassed("127.0.0.1"))
	})
}

func TestGetEndpoints(t *testing.T) {
	setupTestGlobals()
	defer resetServiceConfig()

	t.Run("returns configured endpoints", func(t *testing.T) {
		resetServiceConfig()

		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
			Endpoints: []aikido_types.Endpoint{
				{
					Method: "GET",
					Route:  "/api/users",
				},
				{
					Method: "POST",
					Route:  "/api/orders",
				},
			},
		}

		UpdateServiceConfig(cloudConfig, nil)

		endpoints := GetEndpoints()
		require.Len(t, endpoints, 2)
		assert.Equal(t, "GET", endpoints[0].Method)
		assert.Equal(t, "/api/users", endpoints[0].Route)
		assert.Equal(t, "POST", endpoints[1].Method)
		assert.Equal(t, "/api/orders", endpoints[1].Route)
	})

	t.Run("returns empty slice when no endpoints", func(t *testing.T) {
		resetServiceConfig()

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, nil)

		endpoints := GetEndpoints()
		assert.Empty(t, endpoints)
	})
}

func TestGetCloudConfigUpdatedAt(t *testing.T) {
	setupTestGlobals()
	defer resetServiceConfig()

	t.Run("returns updated timestamp", func(t *testing.T) {
		resetServiceConfig()

		now := time.Now().UnixMilli()
		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt: now,
		}

		UpdateServiceConfig(cloudConfig, nil)

		updatedAt := GetCloudConfigUpdatedAt()
		assert.Equal(t, now, updatedAt)
	})

	t.Run("returns zero time when not initialized", func(t *testing.T) {
		resetServiceConfig()

		updatedAt := GetCloudConfigUpdatedAt()
		assert.Equal(t, int64(0), updatedAt)
	})
}

func TestBuildIPBlocklist(t *testing.T) {
	t.Run("builds IPv4 blocklist", func(t *testing.T) {
		ips := []string{"192.168.1.1", "10.0.0.0/8"}
		blocklist := buildIPBlocklist("test", "Test list", ips)

		assert.Equal(t, "Test list", blocklist.Description)
		assert.NotNil(t, blocklist.TrieV4)
		assert.NotNil(t, blocklist.TrieV6)
	})

	t.Run("builds IPv6 blocklist", func(t *testing.T) {
		ips := []string{"2001:db8::1", "2001:db8::/32"}
		blocklist := buildIPBlocklist("test", "IPv6 list", ips)

		assert.Equal(t, "IPv6 list", blocklist.Description)
		assert.NotNil(t, blocklist.TrieV4)
		assert.NotNil(t, blocklist.TrieV6)
	})

	t.Run("handles mixed IPv4 and IPv6", func(t *testing.T) {
		ips := []string{"192.168.1.1", "2001:db8::1"}
		blocklist := buildIPBlocklist("mixed", "Mixed list", ips)

		assert.Equal(t, "Mixed list", blocklist.Description)
		assert.NotNil(t, blocklist.TrieV4)
		assert.NotNil(t, blocklist.TrieV6)
	})

	t.Run("skips invalid IP addresses", func(t *testing.T) {
		ips := []string{"192.168.1.1", "not-an-ip", "10.0.0.1"}
		blocklist := buildIPBlocklist("test", "Test", ips)

		// Should not panic and should create tries
		assert.NotNil(t, blocklist.TrieV4)
		assert.NotNil(t, blocklist.TrieV6)
	})

	t.Run("handles empty IP list", func(t *testing.T) {
		ips := []string{}
		blocklist := buildIPBlocklist("empty", "Empty list", ips)

		assert.Equal(t, "Empty list", blocklist.Description)
		assert.NotNil(t, blocklist.TrieV4)
		assert.NotNil(t, blocklist.TrieV6)
	})
}

func TestConcurrency(t *testing.T) {
	setupTestGlobals()
	defer resetServiceConfig()

	t.Run("concurrent reads and writes are safe", func(t *testing.T) {
		resetServiceConfig()

		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
			BlockedUserIds:  []string{"user1"},
			BypassedIPs:     []string{"127.0.0.1"},
		}

		UpdateServiceConfig(cloudConfig, nil)

		var wg sync.WaitGroup
		iterations := 100

		// Concurrent readers
		for range iterations {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = IsUserBlocked("user1")
				_ = IsIPBypassed("127.0.0.1")
				_ = GetEndpoints()
				_ = GetCloudConfigUpdatedAt()
			}()
		}

		// Concurrent writers
		for i := range 10 {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				UpdateServiceConfig(&aikido_types.CloudConfigData{
					ConfigUpdatedAt: time.Now().UnixMilli(),
					BlockedUserIds:  []string{"user1", "user2"},
				}, nil)
			}(i)
		}

		wg.Wait()
		// If we get here without panic or race detector errors, the test passes
	})
}
