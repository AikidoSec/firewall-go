//go:build !integration

package zen_test

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/require"
)

// TestShouldProtect_NotLoaded verifies that ShouldProtect returns false
// when zen.Protect() has not been called, preventing panics from
// uninitialized resources like the WASM module.
func TestShouldProtect_NotLoaded(t *testing.T) {
	// Save and restore original state
	origDisabled := zen.IsDisabled()
	origLoaded := config.IsZenLoaded()
	defer func() {
		zen.SetDisabled(origDisabled)
		config.SetZenLoaded(origLoaded)
	}()

	// Set up test state: not disabled, but not loaded
	zen.SetDisabled(false)
	config.SetZenLoaded(false)

	// ShouldProtect must return false when not loaded
	require.False(t, zen.ShouldProtect(), "ShouldProtect should return false when zen.Protect() was never called")
}

// TestShouldProtect_Loaded verifies that ShouldProtect returns true
// when zen.Protect() has been successfully called.
func TestShouldProtect_Loaded(t *testing.T) {
	// Save and restore original state
	origDisabled := zen.IsDisabled()
	origLoaded := config.IsZenLoaded()
	defer func() {
		zen.SetDisabled(origDisabled)
		config.SetZenLoaded(origLoaded)
	}()

	// Set up test state: not disabled, and loaded
	zen.SetDisabled(false)
	config.SetZenLoaded(true)

	// ShouldProtect must return true when loaded and not disabled
	require.True(t, zen.ShouldProtect(), "ShouldProtect should return true when zen.Protect() was called successfully")
}

// TestShouldProtect_DisabledOverridesLoaded verifies that being disabled
// takes precedence over being loaded.
func TestShouldProtect_DisabledOverridesLoaded(t *testing.T) {
	// Save and restore original state
	origDisabled := zen.IsDisabled()
	origLoaded := config.IsZenLoaded()
	defer func() {
		zen.SetDisabled(origDisabled)
		config.SetZenLoaded(origLoaded)
	}()

	// Set up test state: disabled AND loaded
	zen.SetDisabled(true)
	config.SetZenLoaded(true)

	// ShouldProtect must return false when disabled, even if loaded
	require.False(t, zen.ShouldProtect(), "ShouldProtect should return false when disabled, even if loaded")
}
