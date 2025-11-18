package main

import (
	"fmt"
	"io"
	"os"
)

const version = "0.0.0"

func main() {
	if err := run(os.Args, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// run executes the command based on args and returns an error if the command fails
// or if an unknown command is provided. Returns nil on success.
func run(args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 {
		printUsage(stdout)
		return fmt.Errorf("no command provided")
	}

	switch args[1] {
	case "init":
		return initCommand(stdout)
	case "version", "-v", "--version":
		fmt.Fprintf(stdout, "zen-go version %s\n", version)
		return nil
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		fmt.Fprintf(stderr, "Unknown command: %s\n\n", args[1])
		printUsage(stdout)
		return fmt.Errorf("unknown command: %s", args[1])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "zen-go - Aikido Zen CLI tool for Go")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  zen-go <command> [arguments]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  init      Initialize Aikido Firewall (creates orchestrion.tool.go)")
	fmt.Fprintln(w, "  version   Print version information")
	fmt.Fprintln(w, "  help      Show this help message")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  # Initialize Aikido Firewall")
	fmt.Fprintln(w, "  go run github.com/AikidoSec/firewall-go/cmd/zen-go@latest init")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  # Or install globally")
	fmt.Fprintln(w, "  go install github.com/AikidoSec/firewall-go/cmd/zen-go@latest")
	fmt.Fprintln(w, "  zen-go init")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  # Force overwrite existing file")
	fmt.Fprintln(w, "  zen-go init --force")
}
