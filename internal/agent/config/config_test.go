package config

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
)

// TestInitWithEmptyEndpoints tests that Init applies default values when endpoints are empty.
func TestInitWithEmptyEndpoints(t *testing.T) {
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
		Token:            "test-token",
		CollectAPISchema: true,
	}

	Init(environmentConfig, aikidoConfig)

	// Verify defaults were applied
	if globals.EnvironmentConfig.Endpoint != "https://guard.aikido.dev/" {
		t.Errorf("Expected Endpoint to be https://guard.aikido.dev/, but got %q", globals.EnvironmentConfig.Endpoint)
	}

	if globals.EnvironmentConfig.ConfigEndpoint != "https://runtime.aikido.dev/" {
		t.Errorf("Expected ConfigEndpoint to be https://runtime.aikido.dev/, but got %q", globals.EnvironmentConfig.ConfigEndpoint)
	}
}

// TestInitWithProvidedEndpoints tests that Init preserves provided endpoint values.
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

	aikidoConfig := &aikido_types.AikidoConfigData{
		LogLevel:         "INFO",
		Token:            "test-token",
		CollectAPISchema: true,
	}

	Init(environmentConfig, aikidoConfig)

	// Verify custom values were preserved
	if globals.EnvironmentConfig.Endpoint != customEndpoint {
		t.Errorf("Expected Endpoint to be %q, but got %q", customEndpoint, globals.EnvironmentConfig.Endpoint)
	}

	if globals.EnvironmentConfig.ConfigEndpoint != customConfigEndpoint {
		t.Errorf("Expected ConfigEndpoint to be %q, but got %q", customConfigEndpoint, globals.EnvironmentConfig.ConfigEndpoint)
	}
}
