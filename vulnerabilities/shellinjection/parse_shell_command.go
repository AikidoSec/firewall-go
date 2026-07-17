package shellinjection

import (
	"path/filepath"
	"strings"
)

// IsShellCommand checks if the given program path is a shell interpreter.
// It returns true for common shells like sh, bash, zsh, etc.
func IsShellCommand(program string) bool {
	shell := strings.ToLower(filepath.Base(program))

	switch shell {
	case "sh", "bash", "zsh", "dash", "ksh", "fish", "tcsh", "csh", "ash", "busybox":
		return true
	default:
		return false
	}
}

// ExtractShellCommandString extracts the command string from shell invocation arguments.
// It looks for the -c flag and returns everything after it as the command string
// to be interpreted by the shell.
func ExtractShellCommandString(args []string) []string {
	startIndex := 1
	
	// Handle BusyBox multi-call binary pattern: busybox sh -c "command"
	// In this case, we need to skip the shell name argument after busybox
	if len(args) > 0 && strings.ToLower(filepath.Base(args[0])) == "busybox" {
		if len(args) > 1 {
			// Check if the next argument is a shell name
			potentialShell := strings.ToLower(filepath.Base(args[1]))
			if potentialShell == "sh" || potentialShell == "ash" || potentialShell == "bash" {
				startIndex = 2 // Skip both "busybox" and the shell name
			}
		}
	}
	
	for i := startIndex; i < len(args); i++ {
		flag := args[i]
		if flag == "-c" {
			// Return everything after the flag
			if i+1 < len(args) {
				return args[i+1:]
			}
			break
		}
	}

	return nil
}
