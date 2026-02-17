package importcfg

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractBuildFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "empty args",
			args: []string{},
			want: nil,
		},
		{
			name: "only go binary",
			args: []string{"go"},
			want: nil,
		},
		{
			name: "go binary and subcommand no flags",
			args: []string{"go", "build", "./..."},
			want: nil,
		},
		{
			name: "standalone flag",
			args: []string{"go", "build", "-race"},
			want: []string{"-race"},
		},
		{
			name: "multiple standalone flags",
			args: []string{"go", "build", "-race", "-cover", "-trimpath"},
			want: []string{"-race", "-cover", "-trimpath"},
		},
		{
			name: "with-value flag using equals",
			args: []string{"go", "build", "-tags=integration"},
			want: []string{"-tags=integration"},
		},
		{
			name: "with-value flag as separate arg",
			args: []string{"go", "build", "-tags", "integration"},
			want: []string{"-tags=integration"},
		},
		{
			name: "double-dash normalized to single",
			args: []string{"go", "build", "--race"},
			want: []string{"-race"},
		},
		{
			name: "double-dash with-value normalized",
			args: []string{"go", "build", "--tags=integration"},
			want: []string{"-tags=integration"},
		},
		{
			name: "stops at double dash separator",
			args: []string{"go", "build", "-race", "--", "-cover"},
			want: []string{"-race"},
		},
		{
			name: "skips unknown flags",
			args: []string{"go", "test", "-v", "-run", "TestFoo", "-race"},
			want: []string{"-race"},
		},
		{
			name: "skips non-flag args",
			args: []string{"go", "build", "./...", "-race"},
			want: []string{"-race"},
		},
		{
			name: "ldflags with equals",
			args: []string{"go", "build", "-ldflags=-s -w"},
			want: []string{"-ldflags=-s -w"},
		},
		{
			name: "gcflags as separate arg",
			args: []string{"go", "build", "-gcflags", "all=-N -l"},
			want: []string{"-gcflags=all=-N -l"},
		},
		{
			name: "no subcommand after go binary",
			args: []string{"go", "-race"},
			want: []string{"-race"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractBuildFlags(tt.args)
			if len(got) != len(tt.want) {
				t.Fatalf("extractBuildFlags(%v) = %v, want %v", tt.args, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("extractBuildFlags(%v)[%d] = %q, want %q", tt.args, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestLocateGoBinary(t *testing.T) {
	path, err := locateGoBinary()
	require.NoError(t, err)
	assert.NotEmpty(t, path)
	assert.FileExists(t, path)
}

func TestMatchesGoBinary(t *testing.T) {
	goBinary, err := locateGoBinary()
	require.NoError(t, err)

	t.Run("matches actual go binary", func(t *testing.T) {
		goPath, err := exec.LookPath("go")
		require.NoError(t, err)
		assert.True(t, matchesGoBinary(goPath, goBinary))
	})

	t.Run("does not match non-go binary", func(t *testing.T) {
		assert.False(t, matchesGoBinary("/bin/sh", goBinary))
	})

	t.Run("returns false for nonexistent path", func(t *testing.T) {
		assert.False(t, matchesGoBinary("/nonexistent/binary", goBinary))
	})
}
