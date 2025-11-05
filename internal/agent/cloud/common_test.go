package cloud

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/agent/machine"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogCloudRequestError(t *testing.T) {
	tests := []struct {
		name         string
		text         string
		err          error
		callCount    int
		expectedLogs int
	}{
		{
			name:         "ErrNoTokenSet logs only once",
			text:         "token error",
			err:          ErrNoTokenSet,
			callCount:    5,
			expectedLogs: 1, // Should only log the first time
		},
		{
			name:         "other errors log every time",
			text:         "network error",
			err:          errors.New("connection failed"),
			callCount:    3,
			expectedLogs: 3, // Should log all 3 times
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset the atomic boolean before each test
			loggedTokenError.Store(false)

			original := log.Logger()

			// Use a custom handler to count log calls
			var buf bytes.Buffer
			handler := slog.NewTextHandler(&buf, nil)
			log.SetLogger(slog.New(handler))

			// Call the function multiple times
			for i := 0; i < tt.callCount; i++ {
				logCloudRequestError(tt.text, tt.err)
			}

			// Count the number of log entries
			logCount := strings.Count(buf.String(), "level=WARN")

			require.Equal(t, tt.expectedLogs, logCount)

			// Restore original logger
			log.SetLogger(original)
		})
	}

	t.Run("different errors after ErrNoTokenSet still log", func(t *testing.T) {
		loggedTokenError.Store(false)
		original := log.Logger()

		var buf bytes.Buffer
		handler := slog.NewTextHandler(&buf, nil)
		log.SetLogger(slog.New(handler))

		logCloudRequestError("token error", ErrNoTokenSet)
		logCloudRequestError("token error again", ErrNoTokenSet) // should be suppressed
		logCloudRequestError("network error", errors.New("connection failed"))
		logCloudRequestError("timeout error", errors.New("timeout"))

		logCount := strings.Count(buf.String(), "level=WARN")
		require.Equal(t, 3, logCount) // token (1) + network (1) + timeout (1)

		log.SetLogger(original)
	})
}

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
