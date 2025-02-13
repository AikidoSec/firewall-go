package shell_injection

import (
	"github.com/AikidoSec/firewall-go/internal/helpers"
	"strings"
)

var escapeChars = []string{"\"", "'"}
var dangerousCharsInsideDoubleQuotes = []string{"$", "`", "\\", "!"}

// isSafelyEncapsulated checks if the user input is safely encapsulated
func isSafelyEncapsulated(command string, userInput string) bool {
	parts := strings.Split(command, userInput)
	segments := helpers.GetCurrentAndNextSegments(parts)

	for _, segment := range segments {
		charBeforeUserInput := segment.CurrentSegment[len(segment.CurrentSegment)-1:]
		charAfterUserInput := segment.NextSegment[:1]

		isEscapeChar := false
		for _, char := range escapeChars {
			if char == charBeforeUserInput {
				isEscapeChar = true
				break
			}
		}

		if !isEscapeChar {
			return false
		}

		if charBeforeUserInput != charAfterUserInput {
			return false
		}

		if strings.Contains(userInput, charBeforeUserInput) {
			return false
		}

		// Check for dangerous characters inside double quotes
		if charBeforeUserInput == "\"" {
			for _, char := range dangerousCharsInsideDoubleQuotes {
				if strings.Contains(userInput, char) {
					return false
				}
			}
		}
	}

	return true
}
