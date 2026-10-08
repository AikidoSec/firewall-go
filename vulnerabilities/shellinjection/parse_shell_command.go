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
// It handles both separate (-c "command") and attached (-ccommand) forms.
func ExtractShellCommandString(args []string) []string {
	for i := 1; i < len(args); i++ {
		if isCommandFlag(args[i]) {
			// Check if the command string is attached to the flag (e.g., -ccommand)
			attachedCommand := extractAttachedCommand(args[i])
			if attachedCommand != "" {
				// Return the attached command as a single-element slice
				return []string{attachedCommand}
			}
			// Otherwise, return the next argument(s) if available
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

// extractAttachedCommand extracts the command string attached to a -c flag.
// For example, "-cecho test" returns "echo test", "-eccommand" returns "command".
// Returns empty string if no command is attached.
func extractAttachedCommand(flag string) string {
	if len(flag) < 3 || flag[0] != '-' {
		return ""
	}

	// Find the position of 'c' in the flag
	flagPart := flag[1:]
	cIndex := strings.IndexRune(flagPart, 'c')
	if cIndex == -1 {
		return ""
	}

	// Everything after 'c' is the attached command
	// For "-ccommand", cIndex is 0, so we return "command"
	// For "-eccommand", cIndex is 1, so we return "command"
	if cIndex+1 < len(flagPart) {
		return flagPart[cIndex+1:]
	}

	return ""
}
