package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

var toolexecSubcommands = map[string]bool{
	"build":   true,
	"install": true,
	"run":     true,
	"test":    true,
	"vet":     true,
}

func quoteToolexecArg(arg string) (string, error) {
	switch {
	case !strings.ContainsAny(arg, " \t'\""):
		return arg, nil
	case !strings.Contains(arg, "'"):
		return "'" + arg + "'", nil
	case !strings.Contains(arg, `"`):
		return `"` + arg + `"`, nil
	default:
		return "", fmt.Errorf("zen-go path %q contains both single and double quotes and cannot be passed to -toolexec", arg)
	}
}

func buildGoArgs(self string, args []string) ([]string, error) {
	if !toolexecSubcommands[args[0]] {
		return args, nil
	}

	quoted, err := quoteToolexecArg(self)
	if err != nil {
		return nil, err
	}
	toolexec := fmt.Sprintf("-toolexec=%s toolexec", quoted)

	goArgs := make([]string, 0, len(args)+1)
	goArgs = append(goArgs, args[0], toolexec)
	goArgs = append(goArgs, args[1:]...)
	return goArgs, nil
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

	goArgs, err := buildGoArgs(self, args)
	if err != nil {
		return err
	}

	// #nosec G204 - goBin is the Go toolchain resolved from PATH
	cmd := exec.Command(goBin, goArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	return cmd.Run()
}
