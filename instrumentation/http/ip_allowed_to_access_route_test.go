package http

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/ipaddr"
	"github.com/stretchr/testify/assert"
)

// genEndpoint creates a new Endpoint for testing.
func genEndpoint(allowedIPAddresses []string) config.Endpoint {
	return config.Endpoint{
		Method:             "POST",
		Route:              "/posts/:id",
		AllowedIPAddresses: ipaddr.BuildMatchList("", "", allowedIPAddresses),
		ForceProtectionOff: true,
	}
}

func TestIPAccessController(t *testing.T) {
	t.Run("testEmptyEndpoints", func(t *testing.T) {
		assert.True(t, ipAllowedToAccessRoute("1.2.3.4", nil))
		assert.True(t, ipAllowedToAccessRoute("1.2.3.4", []config.Endpoint{}))
	})

	t.Run("testAlwaysAllowsRequestIfNotProduction", func(t *testing.T) {
		endpoints := []config.Endpoint{genEndpoint([]string{"1.2.3.4"})}
		assert.True(t, ipAllowedToAccessRoute("::1", endpoints))
	})

	t.Run("testAlwaysAllowsRequestIfNoMatch", func(t *testing.T) {
		endpoints := []config.Endpoint{genEndpoint([]string{"1.2.3.4"})}
		assert.True(t, ipAllowedToAccessRoute("1.2.3.4", endpoints))
	})

	t.Run("testAlwaysAllowsRequestIfAllowedIpAddress", func(t *testing.T) {
		endpoints := []config.Endpoint{genEndpoint([]string{"1.2.3.4"})}
		assert.True(t, ipAllowedToAccessRoute("1.2.3.4", endpoints))
	})

	t.Run("testAlwaysAllowsRequestIfLocalhost", func(t *testing.T) {
		endpoints := []config.Endpoint{genEndpoint([]string{"1.2.3.4"})}
		assert.True(t, ipAllowedToAccessRoute("::1", endpoints))
	})

	t.Run("testBlocksRequestIfNoIpAddress", func(t *testing.T) {
		endpoints := []config.Endpoint{genEndpoint([]string{"1.2.3.4"})}
		assert.False(t, ipAllowedToAccessRoute("", endpoints))
	})

	t.Run("testAllowsRequestIfConfigurationIsBroken", func(t *testing.T) {
		endpoints := []config.Endpoint{genEndpoint([]string{})} // Broken configuration
		assert.True(t, ipAllowedToAccessRoute("3.4.5.6", endpoints))
	})

	t.Run("testAllowsRequestIfAllowedIpAddressesIsEmpty", func(t *testing.T) {
		endpoints := []config.Endpoint{genEndpoint([]string{})}
		assert.True(t, ipAllowedToAccessRoute("3.4.5.6", endpoints))
	})

	t.Run("testBlocksRequestIfNotAllowedIpAddress", func(t *testing.T) {
		endpoints := []config.Endpoint{genEndpoint([]string{"1.2.3.4"})}
		assert.False(t, ipAllowedToAccessRoute("3.4.5.6", endpoints))
	})

	t.Run("testChecksEveryMatchingEndpoint", func(t *testing.T) {
		endpoints := []config.Endpoint{
			genEndpoint([]string{"3.4.5.6"}),
			genEndpoint([]string{"1.2.3.4"}),
		}
		assert.False(t, ipAllowedToAccessRoute("3.4.5.6", endpoints))
	})

	t.Run("testIfAllowedIpsIsEmptyOrBroken", func(t *testing.T) {
		endpoints := []config.Endpoint{
			genEndpoint([]string{}),
			genEndpoint([]string{}), // Broken configuration
			genEndpoint(nil),        // Broken configuration
			genEndpoint([]string{"1.2.3.4"}),
		}

		assert.True(t, ipAllowedToAccessRoute("1.2.3.4", endpoints))
		assert.False(t, ipAllowedToAccessRoute("3.4.5.6", endpoints))
	})

	t.Run("testCIDRIPv4Ranges", func(t *testing.T) {
		endpoints := []config.Endpoint{genEndpoint([]string{"192.168.1.0/24"})}

		// IPs within the CIDR range should be allowed
		assert.True(t, ipAllowedToAccessRoute("192.168.1.1", endpoints))
		assert.True(t, ipAllowedToAccessRoute("192.168.1.100", endpoints))
		assert.True(t, ipAllowedToAccessRoute("192.168.1.254", endpoints))

		// IPs outside the CIDR range should be blocked
		assert.False(t, ipAllowedToAccessRoute("192.168.2.1", endpoints))
		assert.False(t, ipAllowedToAccessRoute("10.0.0.1", endpoints))
		assert.False(t, ipAllowedToAccessRoute("172.16.0.1", endpoints))
	})

	t.Run("testCIDRIPv6Ranges", func(t *testing.T) {
		endpoints := []config.Endpoint{genEndpoint([]string{"2001:db8::/32"})}

		// IPs within the CIDR range should be allowed
		assert.True(t, ipAllowedToAccessRoute("2001:db8::1", endpoints))
		assert.True(t, ipAllowedToAccessRoute("2001:db8:1::1", endpoints))
		assert.True(t, ipAllowedToAccessRoute("2001:db8:ffff::ffff", endpoints))

		// IPs outside the CIDR range should be blocked
		assert.False(t, ipAllowedToAccessRoute("2001:db9::1", endpoints))
		assert.False(t, ipAllowedToAccessRoute("2001:0db7::1", endpoints))
	})

	t.Run("testMixedCIDRAndIndividualIPs", func(t *testing.T) {
		endpoints := []config.Endpoint{genEndpoint([]string{
			"192.168.1.0/24", // CIDR range
			"10.0.0.1",       // Individual IP
			"2001:db8::/32",  // IPv6 CIDR range
			"::1",            // IPv6 individual IP (localhost)
		})}

		// Should allow IPs within CIDR ranges
		assert.True(t, ipAllowedToAccessRoute("192.168.1.50", endpoints))
		assert.True(t, ipAllowedToAccessRoute("10.0.0.1", endpoints))
		assert.True(t, ipAllowedToAccessRoute("2001:db8:1234::5678", endpoints))
		assert.True(t, ipAllowedToAccessRoute("::1", endpoints))

		// Should block IPs not in any range
		assert.False(t, ipAllowedToAccessRoute("192.168.2.1", endpoints))
		assert.False(t, ipAllowedToAccessRoute("10.0.0.2", endpoints))
		assert.False(t, ipAllowedToAccessRoute("2001:db9::1", endpoints))
		assert.False(t, ipAllowedToAccessRoute("::2", endpoints))
	})
}
