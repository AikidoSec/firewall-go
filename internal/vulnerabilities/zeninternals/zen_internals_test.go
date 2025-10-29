package zeninternals

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifyWASMChecksum(t *testing.T) {
	parts := strings.Fields(checksumFile)
	require.Len(t, parts, 2, "invalid checksum file format")

	expectedHash := parts[0]

	hash := sha256.Sum256(wasmBin)
	actualHash := hex.EncodeToString(hash[:])

	require.Equal(t, expectedHash, actualHash, "checksums must match")
}

func TestNewWasmInstance(t *testing.T) {
	// Initialize the library first
	err := Init()
	if err != nil {
		t.Skipf("Skipping test due to initialization error: %v", err)
	}

	// Test that newWasmInstance returns the correct type
	instance := newWasmInstance()
	require.NotNil(t, instance, "newWasmInstance should not return nil")

	// Type assertion to verify it's a *wasmInstance
	_, ok := instance.(*wasmInstance)
	require.True(t, ok, "newWasmInstance should return *wasmInstance")
}
