package zen

import (
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPopulateConfigFromEnv(t *testing.T) {
	// Set up test environment
	t.Setenv("AIKIDO_LOG_LEVEL", "DEBUG")
	t.Setenv("AIKIDO_LOG_FORMAT", "json")
	t.Setenv("AIKIDO_DEBUG", "true")
	t.Setenv("AIKIDO_TOKEN", "test-token")
	t.Setenv("AIKIDO_ENDPOINT", "https://test.example.com")
	t.Setenv("AIKIDO_REALTIME_ENDPOINT", "https://runtime.test.example.com")

	t.Run("nil config", func(t *testing.T) {
		result := populateConfigFromEnv(nil)
		require.NotNil(t, result)
		require.Equal(t, "DEBUG", result.LogLevel)
		require.Equal(t, "json", result.LogFormat)
		require.True(t, result.Debug)
		require.Equal(t, "test-token", result.Token)
		require.Equal(t, "https://test.example.com", result.Endpoint)
		require.Equal(t, "https://runtime.test.example.com", result.RealtimeEndpoint)
	})

	t.Run("partial config with env fallback", func(t *testing.T) {
		original := &Config{
			LogLevel: "ERROR",          // explicit value should not be overridden
			Token:    "explicit-token", // explicit value should not be overridden
			// other fields should fall back to env vars
		}

		result := populateConfigFromEnv(original)

		// Original should not be modified
		require.Equal(t, "ERROR", original.LogLevel)
		require.Equal(t, "explicit-token", original.Token)

		// Result should have explicit values where provided, env vars elsewhere
		require.Equal(t, "ERROR", result.LogLevel)                                    // explicit value preserved
		require.Equal(t, "json", result.LogFormat)                                    // from env
		require.True(t, result.Debug)                                                 // from env
		require.Equal(t, "explicit-token", result.Token)                              // explicit value preserved
		require.Equal(t, "https://test.example.com", result.Endpoint)                 // from env
		require.Equal(t, "https://runtime.test.example.com", result.RealtimeEndpoint) // from env
	})

	t.Run("empty config", func(t *testing.T) {
		original := &Config{}
		result := populateConfigFromEnv(original)

		// Original should not be modified
		require.Equal(t, "", original.LogLevel)

		// Result should have env var values
		require.Equal(t, "DEBUG", result.LogLevel)
		require.Equal(t, "json", result.LogFormat)
		require.True(t, result.Debug)
		require.Equal(t, "test-token", result.Token)
		require.Equal(t, "https://test.example.com", result.Endpoint)
		require.Equal(t, "https://runtime.test.example.com", result.RealtimeEndpoint)
	})
}

func TestGetEnvBool(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		want     bool
	}{
		{
			name:     "returns true for 'true'",
			envValue: "true",
			want:     true,
		},
		{
			name:     "returns true for '1'",
			envValue: "1",
			want:     true,
		},
		{
			name:     "returns true for 'TRUE' (case insensitive)",
			envValue: "TRUE",
			want:     true,
		},
		{
			name:     "returns false for 'false'",
			envValue: "false",
			want:     false,
		},
		{
			name:     "returns false for '0'",
			envValue: "0",
			want:     false,
		},
		{
			name:     "returns false for empty string",
			envValue: "",
			want:     false,
		},
		{
			name:     "returns false for other values",
			envValue: "yes",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envVar := "TEST_ENV_BOOL"
			t.Setenv(envVar, tt.envValue)

			assert.Equal(t, tt.want, getEnvBool(envVar))
		})
	}
}

func TestIsDisabled(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		want     bool
	}{
		{
			name:     "returns false when env var not set",
			envValue: "",
			want:     false,
		},
		{
			name:     "returns true for 'true'",
			envValue: "true",
			want:     true,
		},
		{
			name:     "returns true for '1'",
			envValue: "1",
			want:     true,
		},
		{
			name:     "returns false for 'false'",
			envValue: "false",
			want:     false,
		},
		{
			name:     "returns false for '0'",
			envValue: "0",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalDisabled := IsDisabled()
			t.Cleanup(func() { SetDisabled(originalDisabled) })

			if tt.envValue == "" {
				originalValue := os.Getenv("AIKIDO_DISABLE")
				defer func() {
					if originalValue != "" {
						os.Setenv("AIKIDO_DISABLE", originalValue)
					} else {
						os.Unsetenv("AIKIDO_DISABLE")
					}
				}()
				os.Unsetenv("AIKIDO_DISABLE")
			} else {
				t.Setenv("AIKIDO_DISABLE", tt.envValue)
			}

			SetDisabled(getEnvBool("AIKIDO_DISABLE"))

			assert.Equal(t, tt.want, IsDisabled())
		})
	}
}

func TestPopulateConfigFromEnv_Block(t *testing.T) {
	t.Run("AIKIDO_BLOCK env var sets Block field", func(t *testing.T) {
		t.Setenv("AIKIDO_BLOCK", "true")

		result := populateConfigFromEnv(nil)
		require.True(t, result.Block)
	})

	t.Run("explicit Block=true not overridden", func(t *testing.T) {
		t.Setenv("AIKIDO_BLOCK", "false")

		result := populateConfigFromEnv(&Config{Block: true})
		require.True(t, result.Block)
	})

	t.Run("Block defaults to false when env not set", func(t *testing.T) {
		t.Setenv("AIKIDO_BLOCK", "")

		result := populateConfigFromEnv(nil)
		require.False(t, result.Block)
	})
}

func TestDoProtect_InvalidLogLevel(t *testing.T) {
	originalDisabled := IsDisabled()
	t.Cleanup(func() {
		SetDisabled(originalDisabled)
		protectOnce = sync.Once{}
		protectErr = nil
	})

	SetDisabled(false)
	protectOnce = sync.Once{}
	protectErr = nil

	err := ProtectWithConfig(&Config{LogLevel: "INVALID_LEVEL"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid log level")
}

func TestDoProtect_InvalidLogFormat(t *testing.T) {
	originalDisabled := IsDisabled()
	t.Cleanup(func() {
		SetDisabled(originalDisabled)
		protectOnce = sync.Once{}
		protectErr = nil
	})

	SetDisabled(false)
	protectOnce = sync.Once{}
	protectErr = nil

	err := ProtectWithConfig(&Config{LogFormat: "xml"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid log format")
}

func TestProtectWithConfig_AikidoDisabled(t *testing.T) {
	originalDisabled := IsDisabled()
	t.Cleanup(func() { SetDisabled(originalDisabled) })

	t.Setenv("AIKIDO_DISABLE", "true")

	protectOnce = sync.Once{}
	protectErr = nil
	SetDisabled(getEnvBool("AIKIDO_DISABLE"))

	err := ProtectWithConfig(nil)

	require.NoError(t, err)

	// Verify that doProtect was never called
	require.Nil(t, protectErr)
}
