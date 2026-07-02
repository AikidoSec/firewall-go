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
// It looks for the -c flag and returns everything after it as the command string
// to be interpreted by the shell. This includes combined short options like -ec, -xc, etc.
func ExtractShellCommandString(args []string) []string {
	for i := 1; i < len(args); i++ {
		flag := args[i]
		// Check for exact -c flag or combined short options ending with 'c'
		// Examples: -c, -ec, -xc, -euc, etc.
		// We need to ensure:
		// 1. It starts with a single dash (not --)
		// 2. It ends with 'c'
		// 3. It doesn't contain '=' (to avoid long options like --command=value)
		if flag == "-c" || (len(flag) > 2 && flag[0] == '-' && flag[1] != '-' && flag[len(flag)-1] == 'c' && !strings.Contains(flag, "=")) {
			// Return everything after the flag
			if i+1 < len(args) {
				return args[i+1:]
			}
			break
		}
	}

	return nil
}
