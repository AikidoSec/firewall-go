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
		now := time.Now()
		cloudConfig := &aikido_types.CloudConfigData{
			Success:               true,
			ServiceID:             123,
			ConfigUpdatedAt:       now.UnixMilli(),
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
			BlockedIPAddresses: []aikido_types.IPList{
				{
					Key:         "threat-intel",
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
		assert.WithinDuration(t, now, updatedAt, time.Second)

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
		assert.Zero(t, updatedAt)
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
			BlockedIPAddresses: []aikido_types.IPList{
				{
					Key:         "manual",
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
			BlockedIPAddresses: []aikido_types.IPList{
				{
					Key:         "ipv6-test",
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
			BlockedIPAddresses: []aikido_types.IPList{
				{
					Key:         "test",
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
			BlockedIPAddresses: []aikido_types.IPList{
				{
					Key:         "list1",
					Source:      "list1",
					Description: "First list",
					IPs:         []string{"10.0.0.1"},
				},
				{
					Key:         "list2",
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

func TestIsIPAllowed(t *testing.T) {
	setupTestGlobals()
	defer resetServiceConfig()

	t.Run("allows all IPs when allow list is not set", func(t *testing.T) {
		resetServiceConfig()

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, nil)

		// When no allow list is configured, all IPs should be allowed (both public and private)
		assert.True(t, IsIPAllowed("8.8.8.8"))     // Public IP
		assert.True(t, IsIPAllowed("203.0.114.1")) // Public IP
		assert.True(t, IsIPAllowed("192.168.1.1")) // Private IP (always allowed anyway)
		assert.True(t, IsIPAllowed("10.0.0.1"))    // Private IP (always allowed anyway)
	})

	t.Run("allows all IPs when allow list is empty", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			AllowedIPAddresses: []aikido_types.IPList{},
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		// When allow list is empty, all IPs should be allowed (both public and private)
		assert.True(t, IsIPAllowed("8.8.8.8"))     // Public IP
		assert.True(t, IsIPAllowed("203.0.114.1")) // Public IP
		assert.True(t, IsIPAllowed("192.168.1.1")) // Private IP (always allowed anyway)
		assert.True(t, IsIPAllowed("10.0.0.1"))    // Private IP (always allowed anyway)
	})

	t.Run("allows and blocks IPv4 addresses based on allowlist", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			AllowedIPAddresses: []aikido_types.IPList{
				{
					Source:      "manual",
					Description: "Manually allowed",
					IPs:         []string{"8.8.8.8", "1.1.1.0/24"},
				},
			},
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		// IPs in the allow list should be allowed
		assert.True(t, IsIPAllowed("8.8.8.8"))
		// Test CIDR range
		assert.True(t, IsIPAllowed("1.1.1.50"))
		assert.True(t, IsIPAllowed("1.1.1.1"))
		assert.True(t, IsIPAllowed("1.1.1.254"))

		// IPs not in the allow list should be blocked
		assert.False(t, IsIPAllowed("8.8.4.4"))
		assert.False(t, IsIPAllowed("1.1.2.1")) // Outside CIDR range
		assert.False(t, IsIPAllowed("203.0.114.1"))
	})

	t.Run("always allows private IPs even when allowlist is set", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			AllowedIPAddresses: []aikido_types.IPList{
				{
					Source:      "geo-allowed",
					Description: "Allowed countries",
					IPs:         []string{"8.8.8.8"}, // Only allow this public IP
				},
			},
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		// Private IPs should always be allowed, even when not in the allow list
		assert.True(t, IsIPAllowed("127.0.0.1"))   // Loopback
		assert.True(t, IsIPAllowed("192.168.1.1")) // RFC 1918
		assert.True(t, IsIPAllowed("10.0.0.1"))    // RFC 1918
		assert.True(t, IsIPAllowed("172.16.0.1"))  // RFC 1918
		assert.True(t, IsIPAllowed("169.254.0.1")) // Link local
		assert.True(t, IsIPAllowed("::1"))         // IPv6 loopback
		assert.True(t, IsIPAllowed("fc00::1"))     // IPv6 ULA
		assert.True(t, IsIPAllowed("fe80::1"))     // IPv6 link-local

		// Public IP in allow list should be allowed
		assert.True(t, IsIPAllowed("8.8.8.8"))

		// Public IP not in allow list should be blocked
		assert.False(t, IsIPAllowed("8.8.4.4"))
	})

	t.Run("allows and blocks IPv6 addresses based on allowlist", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			AllowedIPAddresses: []aikido_types.IPList{
				{
					Source:      "ipv6-test",
					Description: "IPv6 allowlist",
					IPs:         []string{"2001:4860:4860::8888", "2606:4700:4700::1111"},
				},
			},
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		// IPv6 addresses in the allow list should be allowed
		assert.True(t, IsIPAllowed("2001:4860:4860::8888"))
		assert.True(t, IsIPAllowed("2606:4700:4700::1111"))

		// IPv6 addresses not in the allow list should be blocked
		assert.False(t, IsIPAllowed("2001:4860:4860::8844"))
		assert.False(t, IsIPAllowed("2001:4860:4860::9999"))
	})

	t.Run("handles invalid IP address", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			AllowedIPAddresses: []aikido_types.IPList{
				{
					Source:      "test",
					Description: "Test allowlist",
					IPs:         []string{"8.8.8.8"}, // Public IP in allow list
				},
			},
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		// Invalid IPs should be blocked (return false)
		assert.False(t, IsIPAllowed("not-an-ip"))
		assert.False(t, IsIPAllowed(""))
		// Valid public IP not in allow list should also be blocked
		assert.False(t, IsIPAllowed("8.8.4.4"))
	})

	t.Run("checks multiple allowlists", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			AllowedIPAddresses: []aikido_types.IPList{
				{
					Source:      "list1",
					Description: "First list",
					IPs:         []string{"8.8.8.8"},
				},
				{
					Source:      "list2",
					Description: "Second list",
					IPs:         []string{"1.1.1.1"},
				},
			},
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		// Public IPs in either list should be allowed
		assert.True(t, IsIPAllowed("8.8.8.8"))
		assert.True(t, IsIPAllowed("1.1.1.1"))
		// Public IPs not in any list should be blocked
		assert.False(t, IsIPAllowed("8.8.4.4"))
	})

	t.Run("handles allowlist with empty IPs array", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			AllowedIPAddresses: []aikido_types.IPList{
				{
					Source:      "empty",
					Description: "Empty list",
					IPs:         []string{},
				},
			},
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		// Empty IPs array should be skipped, so allow list should be empty
		// and all IPs should be allowed (both public and private)
		assert.True(t, IsIPAllowed("8.8.8.8"))     // Public IP
		assert.True(t, IsIPAllowed("203.0.114.1")) // Public IP
		assert.True(t, IsIPAllowed("192.168.1.1")) // Private IP (always allowed anyway)
		assert.True(t, IsIPAllowed("10.0.0.1"))    // Private IP (always allowed anyway)
	})

	t.Run("allows when IP matches any list in multiple allowlists", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			AllowedIPAddresses: []aikido_types.IPList{
				{
					Source:      "geo-us",
					Description: "US IPs",
					IPs:         []string{"8.8.8.0/24"},
				},
				{
					Source:      "geo-eu",
					Description: "EU IPs",
					IPs:         []string{"1.1.1.0/24"},
				},
			},
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		// Public IPs from either list should be allowed
		assert.True(t, IsIPAllowed("8.8.8.10"))
		assert.True(t, IsIPAllowed("1.1.1.50"))
		// Public IPs from neither list should be blocked
		assert.False(t, IsIPAllowed("203.0.114.1"))
		// Private IPs should always be allowed regardless
		assert.True(t, IsIPAllowed("192.168.1.1"))
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

	t.Run("bypasses IPv4 in bypass list", func(t *testing.T) {
		resetServiceConfig()

		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
			BypassedIPs:     []string{"127.0.0.1", "192.168.1.100", "10.0.0.0/16"},
		}

		UpdateServiceConfig(cloudConfig, nil)

		assert.True(t, IsIPBypassed("127.0.0.1"))
		assert.True(t, IsIPBypassed("192.168.1.100"))
		assert.True(t, IsIPBypassed("10.0.10.5"))
		assert.False(t, IsIPBypassed("10.1.10.5"))
		assert.False(t, IsIPBypassed("16.16.16.16"))
	})

	t.Run("bypasses IPv6 in bypass list", func(t *testing.T) {
		resetServiceConfig()

		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
			BypassedIPs:     []string{"2001:db8::1", "2002:abcd::/112"},
		}

		UpdateServiceConfig(cloudConfig, nil)

		assert.True(t, IsIPBypassed("2001:db8::1"))
		assert.True(t, IsIPBypassed("2002:abcd::1234"))
		assert.False(t, IsIPBypassed("2001:db8::2"))
		assert.False(t, IsIPBypassed("2002:abce::1234"))
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

		now := time.Now()
		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt: now.UnixMilli(),
		}

		UpdateServiceConfig(cloudConfig, nil)

		updatedAt := GetCloudConfigUpdatedAt()
		assert.WithinDuration(t, now, updatedAt, time.Second)
	})

	t.Run("returns zero time when not initialized", func(t *testing.T) {
		resetServiceConfig()

		updatedAt := GetCloudConfigUpdatedAt()
		assert.Zero(t, updatedAt)
	})
}

func TestShouldBlockHostname(t *testing.T) {
	setupTestGlobals()
	defer resetServiceConfig()

	t.Run("blocks hostname in domains list with mode block", func(t *testing.T) {
		resetServiceConfig()

		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
			Domains: []aikido_types.OutboundDomain{
				{Hostname: "malicious.com", Mode: "block"},
				{Hostname: "allowed.com", Mode: "allow"},
			},
		}

		UpdateServiceConfig(cloudConfig, nil)

		assert.True(t, ShouldBlockHostname("malicious.com"))
		assert.False(t, ShouldBlockHostname("allowed.com"))
	})

	t.Run("blocks hostname when BlockNewOutgoingRequests is true and hostname not in domains", func(t *testing.T) {
		resetServiceConfig()

		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt:          time.Now().UnixMilli(),
			BlockNewOutgoingRequests: true,
			Domains: []aikido_types.OutboundDomain{
				{Hostname: "known.com", Mode: "allow"},
			},
		}

		UpdateServiceConfig(cloudConfig, nil)

		assert.True(t, ShouldBlockHostname("unknown.com"))
		assert.False(t, ShouldBlockHostname("known.com"))
	})

	t.Run("does not block hostname when BlockNewOutgoingRequests is false and hostname not in domains", func(t *testing.T) {
		resetServiceConfig()

		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt:          time.Now().UnixMilli(),
			BlockNewOutgoingRequests: false,
			Domains: []aikido_types.OutboundDomain{
				{Hostname: "known.com", Mode: "allow"},
			},
		}

		UpdateServiceConfig(cloudConfig, nil)

		assert.False(t, ShouldBlockHostname("unknown.com"))
		assert.False(t, ShouldBlockHostname("known.com"))
	})

	t.Run("prioritizes domain list over BlockNewOutgoingRequests", func(t *testing.T) {
		resetServiceConfig()

		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt:          time.Now().UnixMilli(),
			BlockNewOutgoingRequests: false,
			Domains: []aikido_types.OutboundDomain{
				{Hostname: "blocked.com", Mode: "block"},
			},
		}

		UpdateServiceConfig(cloudConfig, nil)

		// Even though BlockNewOutgoingRequests is false, blocked.com should be blocked
		assert.True(t, ShouldBlockHostname("blocked.com"))
		// Unknown hostname should not be blocked when BlockNewOutgoingRequests is false
		assert.False(t, ShouldBlockHostname("unknown.com"))
	})

	t.Run("handles empty domains list", func(t *testing.T) {
		resetServiceConfig()

		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt:          time.Now().UnixMilli(),
			BlockNewOutgoingRequests: true,
			Domains:                  []aikido_types.OutboundDomain{},
		}

		UpdateServiceConfig(cloudConfig, nil)

		assert.True(t, ShouldBlockHostname("anyhostname.com"))
	})

	t.Run("handles multiple domains with different modes", func(t *testing.T) {
		resetServiceConfig()

		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
			Domains: []aikido_types.OutboundDomain{
				{Hostname: "blocked1.com", Mode: "block"},
				{Hostname: "allowed1.com", Mode: "allow"},
				{Hostname: "blocked2.com", Mode: "block"},
				{Hostname: "allowed2.com", Mode: "allow"},
			},
		}

		UpdateServiceConfig(cloudConfig, nil)

		assert.True(t, ShouldBlockHostname("blocked1.com"))
		assert.True(t, ShouldBlockHostname("blocked2.com"))
		assert.False(t, ShouldBlockHostname("allowed1.com"))
		assert.False(t, ShouldBlockHostname("allowed2.com"))
	})
}

func TestGetMatchingMonitoredIPKeys(t *testing.T) {
	setupTestGlobals()
	defer resetServiceConfig()

	t.Run("returns matching monitored IP list keys", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			MonitoredIPAddresses: []aikido_types.IPList{
				{
					Key:         "tor/exit_nodes",
					Source:      "tor",
					Description: "Tor exit nodes",
					IPs:         []string{"9.9.9.9", "1.2.3.4"},
				},
				{
					Key:         "known_threat_actors/public_scanners",
					Source:      "scanners",
					Description: "Public scanners",
					IPs:         []string{"9.9.9.9"},
				},
			},
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		keys := GetMatchingMonitoredIPKeys("9.9.9.9")
		assert.Len(t, keys, 2)
		assert.Contains(t, keys, "tor/exit_nodes")
		assert.Contains(t, keys, "known_threat_actors/public_scanners")

		keys = GetMatchingMonitoredIPKeys("1.2.3.4")
		assert.Equal(t, []string{"tor/exit_nodes"}, keys)

		keys = GetMatchingMonitoredIPKeys("7.7.7.7")
		assert.Empty(t, keys)
	})

	t.Run("returns nil for invalid IP", func(t *testing.T) {
		resetServiceConfig()

		keys := GetMatchingMonitoredIPKeys("not-an-ip")
		assert.Nil(t, keys)
	})
}

func TestGetMatchingBlockedIPKeys(t *testing.T) {
	setupTestGlobals()
	defer resetServiceConfig()

	t.Run("returns matching blocked IP list keys", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			BlockedIPAddresses: []aikido_types.IPList{
				{
					Key:         "geoip/Belgium;BE",
					Source:      "geo-be",
					Description: "Belgium IPs",
					IPs:         []string{"8.8.8.8"},
				},
				{
					Key:         "geoip/Germany;DE",
					Source:      "geo-de",
					Description: "Germany IPs",
					IPs:         []string{"8.8.8.8"},
				},
			},
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		keys := GetMatchingBlockedIPKeys("8.8.8.8")
		assert.Len(t, keys, 2)
		assert.Contains(t, keys, "geoip/Belgium;BE")
		assert.Contains(t, keys, "geoip/Germany;DE")

		keys = GetMatchingBlockedIPKeys("7.7.7.7")
		assert.Empty(t, keys)
	})
}

func TestGetMatchingUserAgentKeys(t *testing.T) {
	setupTestGlobals()
	defer resetServiceConfig()

	t.Run("returns matching user agent keys", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			UserAgentDetails: []aikido_types.UserAgentDetail{
				{Key: "list1", Pattern: "[abc]"},
				{Key: "list2", Pattern: "b"},
			},
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		keys := GetMatchingUserAgentKeys("a")
		assert.Equal(t, []string{"list1"}, keys)

		keys = GetMatchingUserAgentKeys("b")
		assert.Len(t, keys, 2)
		assert.Contains(t, keys, "list1")
		assert.Contains(t, keys, "list2")

		keys = GetMatchingUserAgentKeys("d")
		assert.Empty(t, keys)
	})

	t.Run("case insensitive matching", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			UserAgentDetails: []aikido_types.UserAgentDetail{
				{Key: "googlebot", Pattern: "Googlebot"},
			},
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		keys := GetMatchingUserAgentKeys("googlebot/2.1")
		assert.Equal(t, []string{"googlebot"}, keys)

		keys = GetMatchingUserAgentKeys("GOOGLEBOT/2.1")
		assert.Equal(t, []string{"googlebot"}, keys)
	})

	t.Run("returns empty when no details configured", func(t *testing.T) {
		resetServiceConfig()

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, nil)

		keys := GetMatchingUserAgentKeys("googlebot")
		assert.Empty(t, keys)
	})
}

func TestIsMonitoredUserAgent(t *testing.T) {
	setupTestGlobals()
	defer resetServiceConfig()

	t.Run("returns true for monitored user agent", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			MonitoredUserAgents: "Googlebot|Bingbot",
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		assert.True(t, IsMonitoredUserAgent("Googlebot/2.1"))
		assert.True(t, IsMonitoredUserAgent("Bingbot/1.0"))
		assert.False(t, IsMonitoredUserAgent("Mozilla/5.0 Chrome/91.0"))
	})

	t.Run("case insensitive", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			MonitoredUserAgents: "googlebot",
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		assert.True(t, IsMonitoredUserAgent("GOOGLEBOT"))
		assert.True(t, IsMonitoredUserAgent("googlebot"))
	})

	t.Run("returns false when not configured", func(t *testing.T) {
		resetServiceConfig()

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, nil)

		assert.False(t, IsMonitoredUserAgent("googlebot"))
	})

	t.Run("returns false with empty pattern", func(t *testing.T) {
		resetServiceConfig()

		listsConfig := &aikido_types.ListsConfigData{
			MonitoredUserAgents: "",
		}

		UpdateServiceConfig(&aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
		}, listsConfig)

		assert.False(t, IsMonitoredUserAgent("googlebot"))
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
