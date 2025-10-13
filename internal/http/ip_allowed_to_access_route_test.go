package http

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/stretchr/testify/assert"
)

// genEndpoint creates a new Endpoint for testing.
func genEndpoint(allowedIPAddresses []string) aikido_types.Endpoint {
	return aikido_types.Endpoint{
		Method:             "POST",
		Route:              "/posts/:id",
		AllowedIPAddresses: allowedIPAddresses,
		ForceProtectionOff: true,
	}
}

func TestIPAccessController(t *testing.T) {
	t.Run("testEmptyEndpoints", func(t *testing.T) {
		assert.True(t, ipAllowedToAccessRoute("1.2.3.4", nil))
		assert.True(t, ipAllowedToAccessRoute("1.2.3.4", []aikido_types.Endpoint{}))
	})

	t.Run("testAlwaysAllowsRequestIfNotProduction", func(t *testing.T) {
		endpoints := []aikido_types.Endpoint{genEndpoint([]string{"1.2.3.4"})}
		assert.True(t, ipAllowedToAccessRoute("::1", endpoints))
	})

	t.Run("testAlwaysAllowsRequestIfNoMatch", func(t *testing.T) {
		endpoints := []aikido_types.Endpoint{genEndpoint([]string{"1.2.3.4"})}
		assert.True(t, ipAllowedToAccessRoute("1.2.3.4", endpoints))
	})

	t.Run("testAlwaysAllowsRequestIfAllowedIpAddress", func(t *testing.T) {
		endpoints := []aikido_types.Endpoint{genEndpoint([]string{"1.2.3.4"})}
		assert.True(t, ipAllowedToAccessRoute("1.2.3.4", endpoints))
	})

	t.Run("testAlwaysAllowsRequestIfLocalhost", func(t *testing.T) {
		endpoints := []aikido_types.Endpoint{genEndpoint([]string{"1.2.3.4"})}
		assert.True(t, ipAllowedToAccessRoute("::1", endpoints))
	})

	t.Run("testBlocksRequestIfNoIpAddress", func(t *testing.T) {
		endpoints := []aikido_types.Endpoint{genEndpoint([]string{"1.2.3.4"})}
		assert.False(t, ipAllowedToAccessRoute("", endpoints))
	})

	t.Run("testAllowsRequestIfConfigurationIsBroken", func(t *testing.T) {
		endpoints := []aikido_types.Endpoint{genEndpoint([]string{})} // Broken configuration
		assert.True(t, ipAllowedToAccessRoute("3.4.5.6", endpoints))
	})

	t.Run("testAllowsRequestIfAllowedIpAddressesIsEmpty", func(t *testing.T) {
		endpoints := []aikido_types.Endpoint{genEndpoint([]string{})}
		assert.True(t, ipAllowedToAccessRoute("3.4.5.6", endpoints))
	})

	t.Run("testBlocksRequestIfNotAllowedIpAddress", func(t *testing.T) {
		endpoints := []aikido_types.Endpoint{genEndpoint([]string{"1.2.3.4"})}
		assert.False(t, ipAllowedToAccessRoute("3.4.5.6", endpoints))
	})

	t.Run("testChecksEveryMatchingEndpoint", func(t *testing.T) {
		endpoints := []aikido_types.Endpoint{
			genEndpoint([]string{"3.4.5.6"}),
			genEndpoint([]string{"1.2.3.4"}),
		}
		assert.False(t, ipAllowedToAccessRoute("3.4.5.6", endpoints))
	})

	t.Run("testIfAllowedIpsIsEmptyOrBroken", func(t *testing.T) {
		endpoints := []aikido_types.Endpoint{
			genEndpoint([]string{}),
			genEndpoint([]string{}), // Broken configuration
			genEndpoint(nil),        // Broken configuration
			genEndpoint([]string{"1.2.3.4"}),
		}

		assert.True(t, ipAllowedToAccessRoute("1.2.3.4", endpoints))
		assert.False(t, ipAllowedToAccessRoute("3.4.5.6", endpoints))
	})
}
