package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
)

var toolexecSubcommands = map[string]bool{
	"build":   true,
	"install": true,
	"run":     true,
	"test":    true,
	"vet":     true,
}

func buildGoArgs(self string, args []string) []string {
	if !toolexecSubcommands[args[0]] {
		return args
	}

	toolexec := fmt.Sprintf("-toolexec=%s toolexec", self)

	goArgs := make([]string, 0, len(args)+1)
	goArgs = append(goArgs, args[0], toolexec)
	goArgs = append(goArgs, args[1:]...)
	return goArgs
}

func goCommand(stdout io.Writer, stderr io.Writer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no go command specified")
	}

	goBin, err := exec.LookPath("go")
	if err != nil {
		return fmt.Errorf("could not find go binary: %w", err)
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not determine zen-go path: %w", err)
	}

	// #nosec G204 - goBin is the Go toolchain resolved from PATH
	cmd := exec.Command(goBin, buildGoArgs(self, args)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	return cmd.Run()
}
