package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const version = "0.0.0"

const toolsFileTemplate = `// This file was created by 'zen-go init', and is used to ensure the
// go.mod file contains the necessary entries for repeatable builds.
//go:build tools

package tools

import (
	// Ensures Aikido Zen instrumentation is present in go.mod
	// Do not remove this unless you want to stop using Aikido.
	_ "github.com/AikidoSec/firewall-go/instrumentation"
	_ "github.com/DataDog/orchestrion" // integration
)
`

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "init":
		if err := initCommand(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "version", "-v", "--version":
		fmt.Printf("zen-go version %s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func initCommand() error {
	// Parse flags
	force := false
	if len(os.Args) > 2 {
		for _, arg := range os.Args[2:] {
			if arg == "-f" || arg == "--force" {
				force = true
			}
		}
	}

	filename := "orchestrion.tool.go"

	// Check if file already exists
	if !force {
		if _, err := os.Stat(filename); err == nil {
			fmt.Printf("⚠️  %s already exists\n", filename)
			fmt.Println("   Run with --force to overwrite, or delete the file first.")
			return nil
		}
	}

	// Create the file
	// #nosec G306 - 0644 permissions are appropriate for a non-sensitive source file that will be committed to version control
	if err := os.WriteFile(filename, []byte(toolsFileTemplate), 0o644); err != nil {
		return fmt.Errorf("failed to create %s: %w", filename, err)
	}

	absPath, _ := filepath.Abs(filename)
	fmt.Printf("✓ Created %s\n", filename)
	fmt.Printf("  %s\n\n", absPath)
	fmt.Println("Next steps:")
	fmt.Println("  1. Run 'go mod tidy' to update your dependencies")
	fmt.Println("  2. Build with 'orchestrion go build' to enable instrumentation")

	return nil
}

func printUsage() {
	fmt.Println("zen-go - Aikido Zen CLI tool for Go")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  zen-go <command> [arguments]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  init      Initialize Aikido Firewall (creates orchestrion.tool.go)")
	fmt.Println("  version   Print version information")
	fmt.Println("  help      Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Initialize Aikido Firewall")
	fmt.Println("  go run github.com/AikidoSec/firewall-go/cmd/zen-go@latest init")
	fmt.Println()
	fmt.Println("  # Or install globally")
	fmt.Println("  go install github.com/AikidoSec/firewall-go/cmd/zen-go@latest")
	fmt.Println("  zen-go init")
	fmt.Println()
	fmt.Println("  # Force overwrite existing file")
	fmt.Println("  zen-go init --force")
}
