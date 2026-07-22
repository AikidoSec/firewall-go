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
	case "sh", "bash", "zsh", "dash", "ksh", "fish", "tcsh", "csh":
		return true
	default:
		return false
	}
}

// ExtractShellCommandString extracts the command string from shell invocation arguments.
// It looks for a -c flag (including combined short options like -ec or -cx) and
// returns everything after it as the command string to be interpreted by the shell.
func ExtractShellCommandString(args []string) []string {
	for i := 1; i < len(args); i++ {
		if isCommandFlag(args[i]) {
			if i+1 < len(args) {
				return args[i+1:]
			}
			break
		}
	}

	return nil
}

// isCommandFlag matches -c anywhere in the flag, since shells parse combined short options as an unordered set.
func isCommandFlag(flag string) bool {
	if len(flag) < 2 || flag[0] != '-' || flag[1] == '-' {
		return false
	}
	if strings.Contains(flag, "=") {
		return false
	}
	return strings.ContainsRune(flag[1:], 'c')
}
