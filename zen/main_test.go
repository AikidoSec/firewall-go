package zen

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPopulateConfigFromEnv(t *testing.T) {
	// Set up test environment
	os.Setenv("AIKIDO_LOG_LEVEL", "DEBUG")
	os.Setenv("AIKIDO_LOG_FORMAT", "json")
	os.Setenv("AIKIDO_DEBUG", "true")
	os.Setenv("AIKIDO_TOKEN", "test-token")
	os.Setenv("AIKIDO_ENDPOINT", "https://test.example.com")
	os.Setenv("AIKIDO_REALTIME_ENDPOINT", "https://runtime.test.example.com")
	defer func() {
		os.Unsetenv("AIKIDO_LOG_LEVEL")
		os.Unsetenv("AIKIDO_LOG_FORMAT")
		os.Unsetenv("AIKIDO_DEBUG")
		os.Unsetenv("AIKIDO_TOKEN")
		os.Unsetenv("AIKIDO_ENDPOINT")
		os.Unsetenv("AIKIDO_REALTIME_ENDPOINT")
	}()

	t.Run("nil config", func(t *testing.T) {
		result := populateConfigFromEnv(nil)
		require.NotNil(t, result)
		require.Equal(t, "DEBUG", result.LogLevel)
		require.Equal(t, "json", result.LogFormat)
		require.True(t, result.Debug)
		require.Equal(t, "test-token", result.Token)
		require.Equal(t, "https://test.example.com", result.Endpoint)
		require.Equal(t, "https://runtime.test.example.com", result.ConfigEndpoint)
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
		require.Equal(t, "ERROR", result.LogLevel)                                  // explicit value preserved
		require.Equal(t, "json", result.LogFormat)                                  // from env
		require.True(t, result.Debug)                                               // from env
		require.Equal(t, "explicit-token", result.Token)                            // explicit value preserved
		require.Equal(t, "https://test.example.com", result.Endpoint)               // from env
		require.Equal(t, "https://runtime.test.example.com", result.ConfigEndpoint) // from env
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
		require.Equal(t, "https://runtime.test.example.com", result.ConfigEndpoint)
	})

	t.Run("empty config2", func(t *testing.T) {
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
		require.Equal(t, "https://runtime.test.example.com", result.ConfigEndpoint)
	})
}
