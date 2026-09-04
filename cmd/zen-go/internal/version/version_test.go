package version

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveFromBuildInfo(t *testing.T) {
	tests := []struct {
		name     string
		bi       *debug.BuildInfo
		expected string
	}{
		{
			name:     "uses the version go install resolved",
			bi:       &debug.BuildInfo{Main: debug.Module{Version: "v1.2.7-beta.1"}},
			expected: "v1.2.7-beta.1",
		},
		{
			name:     "falls back to fallback for a local dev build",
			bi:       &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}},
			expected: "1.2.7",
		},
		{
			name:     "falls back to fallback when version is empty",
			bi:       &debug.BuildInfo{Main: debug.Module{Version: ""}},
			expected: "1.2.7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, resolveFromBuildInfo(tt.bi, "1.2.7"))
		})
	}
}

func TestResolveFallsBackDuringLocalBuild(t *testing.T) {
	// The test binary is built locally (not via `go install ...@version`), so
	// build info reports "(devel)" and Resolve falls back to the fallback.
	require.Equal(t, "1.2.7", Resolve("1.2.7"))
}
