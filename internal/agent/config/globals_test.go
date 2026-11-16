package config

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVersionFromBuildInfo(t *testing.T) {
	const modulePath = "github.com/AikidoSec/firewall-go"

	tests := []struct {
		name string
		info debug.BuildInfo
		want string
	}{
		{
			name: "dependency version, not application version",
			info: debug.BuildInfo{
				Main: debug.Module{Path: "example.com/app", Version: "v2.0.0"},
				Deps: []*debug.Module{
					{Path: "example.com/other", Version: "v3.0.0"},
					{Path: modulePath, Version: "v1.3.0"},
				},
			},
			want: "v1.3.0",
		},
		{
			name: "prerelease dependency",
			info: debug.BuildInfo{Deps: []*debug.Module{{Path: modulePath, Version: "v1.3.0-beta.1"}}},
			want: "v1.3.0-beta.1",
		},
		{
			name: "main module",
			info: debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "v1.3.0"}},
			want: "v1.3.0",
		},
		{
			name: "development main module",
			info: debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "(devel)"}},
			want: fallbackVersion,
		},
		{
			name: "missing module",
			info: debug.BuildInfo{Main: debug.Module{Path: "example.com/app", Version: "v2.0.0"}},
			want: fallbackVersion,
		},
		{
			name: "empty dependency version",
			info: debug.BuildInfo{Deps: []*debug.Module{{Path: modulePath}}},
			want: fallbackVersion,
		},
		{
			name: "development dependency version",
			info: debug.BuildInfo{Deps: []*debug.Module{{Path: modulePath, Version: "(devel)"}}},
			want: fallbackVersion,
		},
		{
			name: "versioned replacement",
			info: debug.BuildInfo{Deps: []*debug.Module{{
				Path: modulePath, Version: "v1.3.0",
				Replace: &debug.Module{Path: modulePath, Version: "v1.4.0"},
			}}},
			want: "v1.4.0",
		},
		{
			name: "local replacement",
			info: debug.BuildInfo{Deps: []*debug.Module{{
				Path: modulePath, Version: "v1.3.0",
				Replace: &debug.Module{Path: "../firewall-go"},
			}}},
			want: fallbackVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, versionFromBuildInfo(&tt.info))
		})
	}
}
