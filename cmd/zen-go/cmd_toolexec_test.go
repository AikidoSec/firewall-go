package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createMockTool creates a mock tool script that can be used for testing
func createMockTool(t *testing.T, name string, behavior string) string {
	t.Helper()
	tmpDir := t.TempDir()

	var script string
	if runtime.GOOS == "windows" {
		// Windows batch script
		script = "@echo off\n"
		switch behavior {
		case "success":
			script += "echo compiled successfully\n"
			script += "exit /b 0\n"
		case "failure":
			script += "echo compilation failed\n"
			script += "exit /b 1\n"
		case "echo":
			script += "echo %*\n"
		}
	} else {
		// Unix shell script
		script = "#!/bin/sh\n"
		switch behavior {
		case "success":
			script += "echo 'compiled successfully'\n"
			script += "exit 0\n"
		case "failure":
			script += "echo 'compilation failed' >&2\n"
			script += "exit 1\n"
		case "echo":
			script += "echo \"$@\"\n"
			script += "exit 0\n"
		}
	}

	toolPath := filepath.Join(tmpDir, name)
	if runtime.GOOS == "windows" {
		toolPath += ".bat"
	}

	// #nosec G306 - mock tool needs to be executable
	err := os.WriteFile(toolPath, []byte(script), 0o755)
	require.NoError(t, err)

	return toolPath
}

func TestExtractFlag(t *testing.T) {
	testCases := []struct {
		name     string
		args     []string
		index    int
		flag     string
		expected string
		found    bool
	}{
		{
			name:     "flag with space separator",
			args:     []string{"-p", "main"},
			index:    0,
			flag:     "-p",
			expected: "main",
			found:    true,
		},
		{
			name:     "flag with equals separator",
			args:     []string{"-p=main"},
			index:    0,
			flag:     "-p",
			expected: "main",
			found:    true,
		},
		{
			name:     "flag not found",
			args:     []string{"-o", "output.o"},
			index:    0,
			flag:     "-p",
			expected: "",
			found:    false,
		},
		{
			name:     "flag at end without value",
			args:     []string{"-p"},
			index:    0,
			flag:     "-p",
			expected: "",
			found:    false,
		},
		{
			name:     "equals separator with multiple args",
			args:     []string{"-importcfg=/tmp/cfg", "-o", "out.o"},
			index:    0,
			flag:     "-importcfg",
			expected: "/tmp/cfg",
			found:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			val, found := extractFlag(tc.args, tc.index, tc.flag)
			assert.Equal(t, tc.found, found)
			if found {
				assert.Equal(t, tc.expected, val)
			}
		})
	}
}

func TestIsVersionQuery(t *testing.T) {
	assert.True(t, isVersionQuery([]string{"-V=full"}))
	assert.True(t, isVersionQuery([]string{"-V"}))
	assert.True(t, isVersionQuery([]string{"-p", "main", "-V=full"}))
	assert.False(t, isVersionQuery([]string{"-p", "main", "-o", "out.a"}))
	assert.False(t, isVersionQuery([]string{}))
}

func TestExtractCompilerFlags(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		wantPkg        string
		wantImportcfg  string
		wantOutput     string
	}{
		{
			name:          "all flags space-separated",
			args:          []string{"-p", "main", "-importcfg", "/tmp/cfg", "-o", "/tmp/out.a"},
			wantPkg:       "main",
			wantImportcfg: "/tmp/cfg",
			wantOutput:    "/tmp/out.a",
		},
		{
			name:          "all flags equals form",
			args:          []string{"-p=main", "-importcfg=/tmp/cfg", "-o=/tmp/out.a"},
			wantPkg:       "main",
			wantImportcfg: "/tmp/cfg",
			wantOutput:    "/tmp/out.a",
		},
		{
			name:          "missing flags return empty",
			args:          []string{"-trimpath", "/tmp"},
			wantPkg:       "",
			wantImportcfg: "",
			wantOutput:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg, importcfg, output := extractCompilerFlags(tt.args)
			assert.Equal(t, tt.wantPkg, pkg)
			assert.Equal(t, tt.wantImportcfg, importcfg)
			assert.Equal(t, tt.wantOutput, output)
		})
	}
}

func TestPassthrough(t *testing.T) {
	mockTool := createMockTool(t, "tool", "echo")

	// Capture stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	toolArgs := []string{"arg1", "arg2", "arg3"}
	err = passthrough(os.Stdout, os.Stderr, mockTool, toolArgs)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	var buf bytes.Buffer
	_, err = buf.ReadFrom(r)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "arg1")
	assert.Contains(t, output, "arg2")
	assert.Contains(t, output, "arg3")
}

func TestPassthrough_Error(t *testing.T) {
	mockTool := createMockTool(t, "tool", "failure")

	// Capture stderr
	oldStderr := os.Stderr
	_, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w

	toolArgs := []string{}
	err = passthrough(os.Stdout, os.Stderr, mockTool, toolArgs)

	w.Close()
	os.Stderr = oldStderr

	require.Error(t, err)

	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 1, exitErr.ExitCode())
}

func TestToolexecCLI_UnknownToolPassthrough(t *testing.T) {
	// Test that unknown tools are passed through correctly
	mockTool := createMockTool(t, "link", "echo")

	// Capture stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	args := []string{"zen-go", "toolexec", mockTool, "arg1", "arg2"}
	cmd := newCommand()
	cmd.Writer = os.Stdout
	cmd.ErrWriter = os.Stderr

	err = cmd.Run(context.Background(), args)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	var buf bytes.Buffer
	_, err = buf.ReadFrom(r)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "arg1")
	assert.Contains(t, output, "arg2")
}

func TestPassthrough_PreservesExitCode(t *testing.T) {
	testCases := []struct {
		name         string
		behavior     string
		expectedCode int
	}{
		{
			name:         "success exit code 0",
			behavior:     "success",
			expectedCode: 0,
		},
		{
			name:         "failure exit code 1",
			behavior:     "failure",
			expectedCode: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockTool := createMockTool(t, "tool", tc.behavior)

			// Capture stderr for error output
			oldStderr := os.Stderr
			_, w, err := os.Pipe()
			require.NoError(t, err)
			os.Stderr = w

			toolArgs := []string{}
			err = passthrough(os.Stdout, os.Stderr, mockTool, toolArgs)

			w.Close()
			os.Stderr = oldStderr

			if tc.expectedCode == 0 {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				var exitErr *exec.ExitError
				require.ErrorAs(t, err, &exitErr)
				assert.Equal(t, tc.expectedCode, exitErr.ExitCode())
			}
		})
	}
}

func TestPassthrough_WithComplexArgs(t *testing.T) {
	mockTool := createMockTool(t, "tool", "echo")

	// Capture stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	// Test with complex arguments that might appear in real compile commands
	toolArgs := []string{
		"-p", "github.com/example/pkg",
		"-importcfg", "/tmp/importcfg",
		"-o", "/tmp/output.o",
		"-trimpath", "/tmp",
		"input.go",
	}
	err = passthrough(os.Stdout, os.Stderr, mockTool, toolArgs)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	var buf bytes.Buffer
	_, err = buf.ReadFrom(r)
	require.NoError(t, err)

	output := buf.String()
	// Verify all arguments are passed through
	assert.Contains(t, output, "-p")
	assert.Contains(t, output, "github.com/example/pkg")
	assert.Contains(t, output, "-importcfg")
	assert.Contains(t, output, "/tmp/importcfg")
	assert.Contains(t, output, "-o")
	assert.Contains(t, output, "/tmp/output.o")
	assert.Contains(t, output, "-trimpath")
	assert.Contains(t, output, "input.go")
}

func TestWriteTempFile(t *testing.T) {
	t.Run("writes to objdir/zen-go/src/", func(t *testing.T) {
		objdir := t.TempDir()
		content := []byte("package main")

		out, err := writeTempFile("/src/foo.go", content, objdir)

		require.NoError(t, err)
		assert.Equal(t, filepath.Join(objdir, "zen-go", "src", "foo.go"), out)
		got, err := os.ReadFile(out)
		require.NoError(t, err)
		assert.Equal(t, content, got)
	})

	t.Run("preserves original basename", func(t *testing.T) {
		objdir := t.TempDir()

		out, err := writeTempFile("/some/deep/path/middleware.go", []byte{}, objdir)

		require.NoError(t, err)
		assert.Equal(t, "middleware.go", filepath.Base(out))
	})

	t.Run("falls back to source dir when objdir unusable", func(t *testing.T) {
		srcDir := t.TempDir()
		origPath := filepath.Join(srcDir, "foo.go")
		// Point objdir at an existing file so MkdirAll fails
		badObjdir := filepath.Join(srcDir, "not-a-dir")
		require.NoError(t, os.WriteFile(badObjdir, []byte{}, 0o644))

		out, err := writeTempFile(origPath, []byte("package main"), badObjdir)

		require.NoError(t, err)
		assert.Equal(t, filepath.Join(srcDir, "foo.go"), out)
	})
}

func TestCheckZenToolFileIncluded(t *testing.T) {
	t.Run("errors when zen.tool.go exists but is not in args", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create zen.tool.go in the source directory
		zenToolPath := filepath.Join(tmpDir, "zen.tool.go")
		err := os.WriteFile(zenToolPath, []byte("package main\n"), 0o644)
		require.NoError(t, err)

		mainGoPath := filepath.Join(tmpDir, "main.go")
		toolArgs := []string{"-p", "main", "-o", "/tmp/out.a", mainGoPath}

		err = checkZenToolFileIncluded("main", toolArgs)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "zen.tool.go exists but was not included in the build")
		assert.Contains(t, err.Error(), "instead of specifying individual files")
	})

	t.Run("no error when zen.tool.go is in args", func(t *testing.T) {
		tmpDir := t.TempDir()
		mainGoPath := filepath.Join(tmpDir, "main.go")
		zenToolPath := filepath.Join(tmpDir, "zen.tool.go")

		toolArgs := []string{"-p", "main", "-o", "/tmp/out.a", mainGoPath, zenToolPath}

		err := checkZenToolFileIncluded("main", toolArgs)

		assert.NoError(t, err)
	})

	t.Run("no error when zen.tool.go does not exist", func(t *testing.T) {
		tmpDir := t.TempDir()
		mainGoPath := filepath.Join(tmpDir, "main.go")

		toolArgs := []string{"-p", "main", "-o", "/tmp/out.a", mainGoPath}

		err := checkZenToolFileIncluded("main", toolArgs)

		assert.NoError(t, err)
	})

	t.Run("no error for non-main packages", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create zen.tool.go - but since it's not the main package, no error
		zenToolPath := filepath.Join(tmpDir, "zen.tool.go")
		err := os.WriteFile(zenToolPath, []byte("package main\n"), 0o644)
		require.NoError(t, err)

		goFilePath := filepath.Join(tmpDir, "handler.go")

		toolArgs := []string{"-p", "github.com/example/pkg", "-o", "/tmp/out.a", goFilePath}

		err = checkZenToolFileIncluded("github.com/example/pkg", toolArgs)

		assert.NoError(t, err)
	})

	t.Run("no error when no go files in args", func(t *testing.T) {
		toolArgs := []string{"-p", "main", "-o", "/tmp/out.a"}

		err := checkZenToolFileIncluded("main", toolArgs)

		assert.NoError(t, err)
	})
}
