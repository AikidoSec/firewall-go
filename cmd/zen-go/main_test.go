package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersion(t *testing.T) {
	assert.Equal(t, "0.0.0", version)
}

func TestCLI(t *testing.T) {
	testCases := []struct {
		name           string
		args           []string
		errorContains  string
		stdoutContains []string
		stderrContains []string
		setupDir       func(*testing.T)
	}{
		{
			name:           "version short flag -v",
			args:           []string{"zen-go", "-v"},
			stdoutContains: []string{"zen-go version 0.0.0"},
		},
		{
			name:           "version long flag --version",
			args:           []string{"zen-go", "--version"},
			stdoutContains: []string{"zen-go version 0.0.0"},
		},
		{
			name:           "help command",
			args:           []string{"zen-go", "help"},
			stdoutContains: []string{"zen-go - Aikido Zen CLI tool for Go"},
		},
		{
			name:           "help short flag -h",
			args:           []string{"zen-go", "-h"},
			stdoutContains: []string{"zen-go - Aikido Zen CLI tool for Go"},
		},
		{
			name:           "help long flag --help",
			args:           []string{"zen-go", "--help"},
			stdoutContains: []string{"zen-go - Aikido Zen CLI tool for Go"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setupDir != nil {
				tc.setupDir(t)
			}

			var stdoutBuf, stderrBuf bytes.Buffer
			cmd := newCommand()
			cmd.Writer = &stdoutBuf
			cmd.ErrWriter = &stderrBuf

			err := cmd.Run(context.Background(), tc.args)
			require.NoError(t, err)

			for _, contains := range tc.stdoutContains {
				assert.Contains(t, stdoutBuf.String(), contains)
			}

			for _, contains := range tc.stderrContains {
				assert.Contains(t, stderrBuf.String(), contains)
			}
		})
	}
}
