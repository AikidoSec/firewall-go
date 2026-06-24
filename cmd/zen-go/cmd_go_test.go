package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildGoArgs(t *testing.T) {
	t.Run("injects toolexec after subcommand", func(t *testing.T) {
		got := buildGoArgs("/abs/zen-go", []string{"build", "./..."})
		assert.Equal(t, []string{"build", "-toolexec=/abs/zen-go toolexec", "./..."}, got)
	})

	t.Run("subcommand only", func(t *testing.T) {
		got := buildGoArgs("/abs/zen-go", []string{"build"})
		assert.Equal(t, []string{"build", "-toolexec=/abs/zen-go toolexec"}, got)
	})

	t.Run("preserves trailing flags", func(t *testing.T) {
		got := buildGoArgs("/abs/zen-go", []string{"test", "-race", "-tags=integration", "./..."})
		assert.Equal(t, []string{"test", "-toolexec=/abs/zen-go toolexec", "-race", "-tags=integration", "./..."}, got)
	})

	t.Run("passes through non-compiling subcommands untouched", func(t *testing.T) {
		args := []string{"help", "build"}
		assert.Equal(t, args, buildGoArgs("/abs/zen-go", args))

		args = []string{"mod", "tidy"}
		assert.Equal(t, args, buildGoArgs("/abs/zen-go", args))
	})
}

func TestGoCommandNoArgs(t *testing.T) {
	err := goCommand(nil, nil, nil)
	assert.ErrorContains(t, err, "no go command specified")
}
