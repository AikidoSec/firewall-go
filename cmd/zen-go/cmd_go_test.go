package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildGoArgs(t *testing.T) {
	t.Run("injects toolexec after subcommand", func(t *testing.T) {
		got, err := buildGoArgs("/abs/zen-go", []string{"build", "./..."})
		assert.NoError(t, err)
		assert.Equal(t, []string{"build", "-toolexec=/abs/zen-go toolexec", "./..."}, got)
	})

	t.Run("subcommand only", func(t *testing.T) {
		got, err := buildGoArgs("/abs/zen-go", []string{"build"})
		assert.NoError(t, err)
		assert.Equal(t, []string{"build", "-toolexec=/abs/zen-go toolexec"}, got)
	})

	t.Run("preserves trailing flags", func(t *testing.T) {
		got, err := buildGoArgs("/abs/zen-go", []string{"test", "-race", "-tags=integration", "./..."})
		assert.NoError(t, err)
		assert.Equal(t, []string{"test", "-toolexec=/abs/zen-go toolexec", "-race", "-tags=integration", "./..."}, got)
	})

	t.Run("quotes path containing spaces", func(t *testing.T) {
		got, err := buildGoArgs("/abs/My Tools/zen-go", []string{"build", "./..."})
		assert.NoError(t, err)
		assert.Equal(t, []string{"build", "-toolexec='/abs/My Tools/zen-go' toolexec", "./..."}, got)
	})

	t.Run("errors when path contains both quote styles", func(t *testing.T) {
		_, err := buildGoArgs(`/abs/it's "weird"/zen-go`, []string{"build", "./..."})
		assert.ErrorContains(t, err, "cannot be passed to -toolexec")
	})

	t.Run("passes through non-compiling subcommands untouched", func(t *testing.T) {
		args := []string{"help", "build"}
		got, err := buildGoArgs("/abs/zen-go", args)
		assert.NoError(t, err)
		assert.Equal(t, args, got)

		args = []string{"mod", "tidy"}
		got, err = buildGoArgs("/abs/zen-go", args)
		assert.NoError(t, err)
		assert.Equal(t, args, got)
	})
}

func TestGoCommandNoArgs(t *testing.T) {
	err := goCommand(nil, nil, nil)
	assert.ErrorContains(t, err, "no go command specified")
}
