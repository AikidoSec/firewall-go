package zen

import (
	"testing"

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

			got := getEnvBool(envVar)
			if got != tt.want {
				t.Errorf("getEnvBool() = %v, want %v", got, tt.want)
			}
		})
	}
}
