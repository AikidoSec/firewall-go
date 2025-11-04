package main

import (
	"fmt"
	"os"
)

const version = "0.0.0"

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
