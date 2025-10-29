package config

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/stretchr/testify/require"
)

// TestExtractRegionFromToken tests the extractRegionFromToken function.
func TestExtractRegionFromToken(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected string
	}{
		{
			name:     "should return EU for empty token",
			token:    "",
			expected: "EU",
		},
		{
			name:     "should return EU for invalid token",
			token:    "invalid-token",
			expected: "EU",
		},
		{
			name:     "should return EU for token not starting with AIK_RUNTIME_",
			token:    "SOME_OTHER_TOKEN_123_456_US_abc",
			expected: "EU",
		},
		{
			name:     "should return EU for old format token without region",
			token:    "AIK_RUNTIME_123_456_randomstring",
			expected: "EU",
		},
		{
			name:     "should return US for new format token with US region",
			token:    "AIK_RUNTIME_123_456_US_randomstring",
			expected: "US",
		},
		{
			name:     "should return ME for new format token with ME region",
			token:    "AIK_RUNTIME_123_456_ME_randomstring",
			expected: "ME",
		},
		{
			name:     "should return EU for new format token with EU region",
			token:    "AIK_RUNTIME_123_456_EU_randomstring",
			expected: "EU",
		},
		{
			name:     "should return whatever prefix is there (CUSTOM)",
			token:    "AIK_RUNTIME_123_456_CUSTOM_randomstring",
			expected: "CUSTOM",
		},
		{
			name:     "should return whatever prefix is there (123)",
			token:    "AIK_RUNTIME_123_456_123_randomstring",
			expected: "123",
		},
		{
			name:     "should return EU if region part is missing (3 parts)",
			token:    "AIK_RUNTIME_123_456",
			expected: "EU",
		},
		{
			name:     "should return EU if region part is missing (2 parts)",
			token:    "AIK_RUNTIME_123",
			expected: "EU",
		},
		{
			name:     "should return EU if region part is missing (prefix only)",
			token:    "AIK_RUNTIME_",
			expected: "EU",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractRegionFromToken(tt.token)
			if result != tt.expected {
				t.Errorf("Expected %q, but got %q", tt.expected, result)
			}
		})
	}
}

// TestGetEndpointURL tests the getEndpointURL function.
func TestGetEndpointURL(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected string
	}{
		{
			name:     "US region token returns US endpoint",
			token:    "AIK_RUNTIME_123_456_US_789",
			expected: "https://guard.us.aikido.dev/",
		},
		{
			name:     "ME region token returns ME endpoint",
			token:    "AIK_RUNTIME_123_456_ME_789",
			expected: "https://guard.me.aikido.dev/",
		},
		{
			name:     "EU region token returns default endpoint",
			token:    "AIK_RUNTIME_123_456_EU_789",
			expected: "https://guard.aikido.dev/",
		},
		{
			name:     "Old format token returns default endpoint",
			token:    "AIK_RUNTIME_123_456_789",
			expected: "https://guard.aikido.dev/",
		},
		{
			name:     "Empty token returns default endpoint",
			token:    "",
			expected: "https://guard.aikido.dev/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getEndpointURL(tt.token)
			if result != tt.expected {
				t.Errorf("Expected %q, but got %q", tt.expected, result)
			}
		})
	}
}

// TestInitWithEmptyEndpoints tests that Init applies default values when endpoints are empty.
func TestInitWithEmptyEndpoints(t *testing.T) {
	tests := []struct {
		name             string
		token            string
		expectedEndpoint string
	}{
		{
			name:             "Old format token defaults to EU endpoint",
			token:            "AIK_RUNTIME_123_456_789",
			expectedEndpoint: "https://guard.aikido.dev/",
		},
		{
			name:             "US region token uses US endpoint",
			token:            "AIK_RUNTIME_123_456_US_789",
			expectedEndpoint: "https://guard.us.aikido.dev/",
		},
		{
			name:             "ME region token uses ME endpoint",
			token:            "AIK_RUNTIME_123_456_ME_789",
			expectedEndpoint: "https://guard.me.aikido.dev/",
		},
		{
			name:             "EU region token uses default endpoint",
			token:            "AIK_RUNTIME_123_456_EU_789",
			expectedEndpoint: "https://guard.aikido.dev/",
		},
		{
			name:             "Empty token defaults to EU endpoint",
			token:            "",
			expectedEndpoint: "https://guard.aikido.dev/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			environmentConfig := &aikido_types.EnvironmentConfigData{
				PlatformName:    "test-platform",
				PlatformVersion: "1.0.0",
				Library:         "test-lib",
				Endpoint:        "", // Empty endpoint
				ConfigEndpoint:  "", // Empty config endpoint
				Version:         "1.0.0",
			}

			aikidoConfig := &aikido_types.AikidoConfigData{
				LogLevel:         "INFO",
				Token:            tt.token,
				CollectAPISchema: true,
			}

			err := Init(environmentConfig, aikidoConfig)
			require.NoError(t, err)

			// Verify correct endpoint was applied based on token region
			if globals.EnvironmentConfig.Endpoint != tt.expectedEndpoint {
				t.Errorf("Expected Endpoint to be %q, but got %q", tt.expectedEndpoint, globals.EnvironmentConfig.Endpoint)
			}

			// ConfigEndpoint should always be the default
			if globals.EnvironmentConfig.ConfigEndpoint != "https://runtime.aikido.dev/" {
				t.Errorf("Expected ConfigEndpoint to be https://runtime.aikido.dev/, but got %q", globals.EnvironmentConfig.ConfigEndpoint)
			}
		})
	}
}

// TestInitWithProvidedEndpoints tests that Init preserves provided endpoint values.
// Explicitly provided endpoints should override region-based endpoint selection.
func TestInitWithProvidedEndpoints(t *testing.T) {
	customEndpoint := "https://custom.example.com/"
	customConfigEndpoint := "https://custom-config.example.com/"

	environmentConfig := &aikido_types.EnvironmentConfigData{
		PlatformName:    "test-platform",
		PlatformVersion: "1.0.0",
		Library:         "test-lib",
		Endpoint:        customEndpoint,
		ConfigEndpoint:  customConfigEndpoint,
		Version:         "1.0.0",
	}

	// Use a US token, but the custom endpoint should still be used
	aikidoConfig := &aikido_types.AikidoConfigData{
		LogLevel:         "INFO",
		Token:            "AIK_RUNTIME_123_456_US_789",
		CollectAPISchema: true,
	}

	err := Init(environmentConfig, aikidoConfig)
	require.NoError(t, err)

	// Verify custom values were preserved (not the US endpoint)
	if globals.EnvironmentConfig.Endpoint != customEndpoint {
		t.Errorf("Expected Endpoint to be %q, but got %q", customEndpoint, globals.EnvironmentConfig.Endpoint)
	}

	if globals.EnvironmentConfig.ConfigEndpoint != customConfigEndpoint {
		t.Errorf("Expected ConfigEndpoint to be %q, but got %q", customConfigEndpoint, globals.EnvironmentConfig.ConfigEndpoint)
	}
}

func TestInitReturnsErrorForInvalidConfig(t *testing.T) {
	err := Init(nil, &aikido_types.AikidoConfigData{
		LogLevel: "INVALID",
	})

	require.Error(t, err)
}
