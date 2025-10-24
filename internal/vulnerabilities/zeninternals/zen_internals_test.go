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
