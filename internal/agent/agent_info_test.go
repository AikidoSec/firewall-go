package agent

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/agent/machine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAgentInfo(t *testing.T) {
	// Initialize machine data
	machine.Init()

	// Set up environment config
	environmentConfig := &aikido_types.EnvironmentConfigData{
		PlatformName:    "test-platform",
		PlatformVersion: "1.2.3",
		Library:         "test-lib",
		Version:         "2.0.0",
	}

	aikidoConfig := &aikido_types.AikidoConfigData{
		LogLevel: "INFO",
		Token:    "test-token",
	}

	err := config.Init(environmentConfig, aikidoConfig)
	require.NoError(t, err)

	t.Run("DryMode reflects blocking state", func(t *testing.T) {
		config.SetBlocking(false)
		info := getAgentInfo()
		assert.True(t, info.DryMode, "DryMode should be true when blocking is disabled")

		config.SetBlocking(true)
		info = getAgentInfo()
		assert.False(t, info.DryMode, "DryMode should be false when blocking is enabled")
	})

	t.Run("all fields populated correctly", func(t *testing.T) {
		config.SetBlocking(false)

		info := getAgentInfo()

		// Verify all fields are set from correct sources
		assert.Equal(t, !config.IsBlockingEnabled(), info.DryMode)
		assert.Equal(t, machine.Machine.HostName, info.Hostname)
		assert.Equal(t, globals.EnvironmentConfig.Version, info.Version)
		assert.Equal(t, machine.Machine.IPAddress, info.IPAddress)
		assert.Equal(t, machine.Machine.OS, info.OS.Name)
		assert.Equal(t, machine.Machine.OSVersion, info.OS.Version)
		assert.Equal(t, globals.EnvironmentConfig.PlatformName, info.Platform.Name)
		assert.Equal(t, globals.EnvironmentConfig.PlatformVersion, info.Platform.Version)
		assert.Equal(t, globals.EnvironmentConfig.Library, info.Library)
		assert.NotNil(t, info.Packages)
		assert.Empty(t, info.Packages, "Packages should be an empty map")
		assert.Empty(t, info.NodeEnv, "NodeEnv should be empty string")
	})
}
