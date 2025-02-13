package shell_injection

import "strings"

func detectShellInjection(command, userInput string) bool {
	// Block single ~ character. For example echo ~
	if userInput == "~" {
		if len(command) > 1 && strings.Contains(command, "~") {
			return true
		}
	}

	if len(userInput) <= 1 {
		// We ignore single characters since they don't pose a big threat.
		// They are only able to crash the shell, not execute arbitrary commands.
		return false
	}

	if len(userInput) > len(command) {
		// We ignore cases where the user input is longer than the command.
		// Because the user input can't be part of the command.
		return false
	}

	if !strings.Contains(command, userInput) {
		return false
	}

	if isSafelyEncapsulated(command, userInput) {
		return false
	}

	return containsShellSyntax(command, userInput)
}
