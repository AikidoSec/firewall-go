package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractLinkerImportcfg(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name:     "flag with space separator",
			args:     []string{"-o", "output", "-importcfg", "/path/to/importcfg"},
			expected: "/path/to/importcfg",
		},
		{
			name:     "flag with equals separator",
			args:     []string{"-o=output", "-importcfg=/path/to/importcfg"},
			expected: "/path/to/importcfg",
		},
		{
			name:     "no importcfg flag",
			args:     []string{"-o", "output", "-L", "/lib"},
			expected: "",
		},
		{
			name:     "empty args",
			args:     []string{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractLinkerImportcfg(tt.args)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCollectLinkDeps(t *testing.T) {
	tmpDir := t.TempDir()

	// Create mock archive files with link deps
	archive1 := filepath.Join(tmpDir, "pkg1.a")
	// #nosec G306 -- test file
	require.NoError(t, os.WriteFile(archive1, []byte{}, 0o644))
	// #nosec G306 -- test file
	require.NoError(t, os.WriteFile(archive1+".zenlinkdeps", []byte("github.com/example/dep1\ngithub.com/example/dep2"), 0o644))

	archive2 := filepath.Join(tmpDir, "pkg2.a")
	// #nosec G306 -- test file
	require.NoError(t, os.WriteFile(archive2, []byte{}, 0o644))
	// #nosec G306 -- test file
	require.NoError(t, os.WriteFile(archive2+".zenlinkdeps", []byte("github.com/example/dep2\ngithub.com/example/dep3"), 0o644))

	// Archive without link deps
	archive3 := filepath.Join(tmpDir, "pkg3.a")
	// #nosec G306 -- test file
	require.NoError(t, os.WriteFile(archive3, []byte{}, 0o644))

	importcfgContent := []byte("# import config\n" +
		"packagefile pkg1=" + archive1 + "\n" +
		"packagefile pkg2=" + archive2 + "\n" +
		"packagefile pkg3=" + archive3 + "\n")

	deps := collectLinkDeps(importcfgContent, os.Stderr)

	assert.Len(t, deps, 3)
	assert.True(t, deps["github.com/example/dep1"])
	assert.True(t, deps["github.com/example/dep2"])
	assert.True(t, deps["github.com/example/dep3"])
}

func TestCollectLinkDeps_NoDeps(t *testing.T) {
	tmpDir := t.TempDir()

	archive := filepath.Join(tmpDir, "pkg.a")
	// #nosec G306 -- test file
	require.NoError(t, os.WriteFile(archive, []byte{}, 0o644))

	importcfgContent := []byte("# import config\npackagefile pkg=" + archive + "\n")

	deps := collectLinkDeps(importcfgContent, os.Stderr)

	assert.Empty(t, deps)
}

func TestResolveMissingDeps(t *testing.T) {
	importcfgContent := []byte("# import config\n" +
		"packagefile github.com/existing/pkg=/path/to/existing.a\n")

	allLinkDeps := map[string]bool{
		"github.com/existing/pkg": true, // Should be skipped
		"github.com/missing/pkg":  true, // Would need resolution, but will fail
	}

	// This will try to resolve the missing package which will fail,
	// so we just verify it doesn't crash and handles the error gracefully
	newLines := resolveMissingDeps(importcfgContent, allLinkDeps, os.Stderr)

	// The existing package should be skipped, and the missing one will fail to resolve
	// so we expect either 0 or 1 entries (depending on if go list can find it)
	assert.GreaterOrEqual(t, 1, len(newLines))
}

func TestReplaceLinkerImportcfgArg(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		newPath  string
		expected []string
	}{
		{
			name:     "space separator",
			args:     []string{"-o", "out", "-importcfg", "/old/path", "file.a"},
			newPath:  "/new/path",
			expected: []string{"-o", "out", "-importcfg", "/new/path", "file.a"},
		},
		{
			name:     "equals separator",
			args:     []string{"-o=out", "-importcfg=/old/path", "file.a"},
			newPath:  "/new/path",
			expected: []string{"-o=out", "-importcfg=/new/path", "file.a"},
		},
		{
			name:     "no importcfg",
			args:     []string{"-o", "out", "file.a"},
			newPath:  "/new/path",
			expected: []string{"-o", "out", "file.a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := replaceLinkerImportcfgArg(tt.args, tt.newPath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWriteExtendedLinkerImportcfg(t *testing.T) {
	originalContent := []byte("# import config\npackagefile fmt=/path/to/fmt.a")
	newLines := []string{
		"packagefile os=/path/to/os.a",
		"packagefile io=/path/to/io.a",
	}

	tmpPath, err := writeExtendedLinkerImportcfg(originalContent, newLines)
	require.NoError(t, err)
	defer os.Remove(tmpPath)

	content, err := os.ReadFile(tmpPath)
	require.NoError(t, err)

	assert.Contains(t, string(content), "packagefile fmt=/path/to/fmt.a")
	assert.Contains(t, string(content), "packagefile os=/path/to/os.a")
	assert.Contains(t, string(content), "packagefile io=/path/to/io.a")
}

func TestInsertLinkerFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		flags    []string
		expected []string
	}{
		{
			name:     "inserts before archive file",
			args:     []string{"-o", "output", "-importcfg", "/tmp/cfg", "main.a"},
			flags:    []string{"-X", "pkg.Var=value"},
			expected: []string{"-o", "output", "-importcfg", "/tmp/cfg", "-X", "pkg.Var=value", "main.a"},
		},
		{
			name:     "works with existing -X flags",
			args:     []string{"-X", "main.version=1.0", "main.a"},
			flags:    []string{"-X", "pkg.Var=value"},
			expected: []string{"-X", "main.version=1.0", "-X", "pkg.Var=value", "main.a"},
		},
		{
			name:     "empty args",
			args:     []string{},
			flags:    []string{"-X", "pkg.Var=value"},
			expected: []string{"-X", "pkg.Var=value"},
		},
		{
			name:     "single arg",
			args:     []string{"main.a"},
			flags:    []string{"-X", "pkg.Var=value"},
			expected: []string{"-X", "pkg.Var=value", "main.a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := insertLinkerFlags(tt.args, tt.flags...)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWriteLinkDepsForArchive_NoLinkDeps(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "test.a")
	// #nosec G306 -- test file
	require.NoError(t, os.WriteFile(outputPath, []byte{}, 0o644))

	linkDeps := []string{}

	// Should not create a linkdeps file
	writeLinkDepsForArchive(os.Stderr, outputPath, linkDeps)

	_, err := os.Stat(outputPath + ".zenlinkdeps")
	assert.True(t, os.IsNotExist(err))
}

func TestWriteLinkDepsForArchive_EmptyOutputPath(t *testing.T) {
	linkDeps := []string{"github.com/example/pkg"}

	// Should not panic with empty output path
	writeLinkDepsForArchive(os.Stderr, "", linkDeps)
}

func TestWriteLinkDepsForArchive_NonExistentOutput(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "nonexistent.a")

	linkDeps := []string{"github.com/example/pkg"}

	// Should not create linkdeps file if output doesn't exist
	writeLinkDepsForArchive(os.Stderr, outputPath, linkDeps)

	_, err := os.Stat(outputPath + ".zenlinkdeps")
	assert.True(t, os.IsNotExist(err))
}

func TestWriteLinkDepsForArchive_Success(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "test.a")
	// #nosec G306 -- test file
	require.NoError(t, os.WriteFile(outputPath, []byte{}, 0o644))

	linkDeps := []string{
		"github.com/example/pkg1",
		"github.com/example/pkg2",
	}

	writeLinkDepsForArchive(os.Stderr, outputPath, linkDeps)

	content, err := os.ReadFile(outputPath + ".zenlinkdeps")
	require.NoError(t, err)

	assert.Contains(t, string(content), "github.com/example/pkg1")
	assert.Contains(t, string(content), "github.com/example/pkg2")
}
