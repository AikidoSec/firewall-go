package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/urfave/cli/v3"
)

func toolexecCompileCommand(cmd *cli.Command, stdout io.Writer, stderr io.Writer, tool string, toolArgs []string) error {
	// If has -V=full or just -V, then it's a version query
	// Check for -V flag, with optional "full" value
	for _, arg := range toolArgs {
		if arg == "-V=full" || arg == "-V" {
			return toolexecVersionQueryCommand(
				stdout,
				stderr,
				tool, toolArgs,
			)
		}
	}

	var pkgPath, importcfgPath, outputPath string
	for i := range len(toolArgs) {
		if val, ok := extractFlag(toolArgs, i, "-p"); ok {
			pkgPath = val
		} else if val, ok := extractFlag(toolArgs, i, "-importcfg"); ok {
			importcfgPath = val
		} else if val, ok := extractFlag(toolArgs, i, "-o"); ok {
			outputPath = val
		}
	}

	if isDebug() {
		fmt.Fprintf(stderr, "zen-go: compiling package %s\n", pkgPath)
		fmt.Fprintf(stderr, "%s, %s", importcfgPath, outputPath)
	}

	// These are the arguments that we want to pass through to the compiler
	// If we modify a file, we need to pass the modified file to the compiler instead of the original file
	newArgs := make([]string, 0, len(toolArgs))

	for _, arg := range toolArgs {
		// If doesn't end with .go, it's not a Go file
		// so we can pass it through to the compiler
		if !strings.HasSuffix(arg, ".go") {
			newArgs = append(newArgs, arg)
			continue
		}

		// It's a Go file, for now we just pass it through to the compiler
		fmt.Fprintf(stderr, "zen-go: instrumenting file %s\n", arg)
		newArgs = append(newArgs, arg)
	}

	// Run the compiler
	err := passthrough(tool, newArgs)
	if err != nil {
		return err
	}

	return nil
}

func extractFlag(args []string, i int, flag string) (string, bool) {
	if args[i] == flag && i+1 < len(args) {
		return args[i+1], true
	}
	if val, ok := strings.CutPrefix(args[i], flag+"="); ok {
		return val, true
	}
	return "", false
}

// passthrough runs the given Golang tool
// For example, it will run the compiler with the arguments originally passed our toolexec command
func passthrough(tool string, args []string) error {
	cmd := exec.Command(tool, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
