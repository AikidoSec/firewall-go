package shell_injection

import (
	. "github.com/AikidoSec/firewall-go/internal/helpers"
	"strings"
)

func isSafelyEncapsulated(command string, userInput string) bool {
	escapeChars := []string{"\"", "'"}
	dangerousCharsInsideDoubleQuotes := []string{"$", "`", "\\", "!"}

	parts := strings.Split(command, userInput)
	segments := GetCurrentAndNextSegments(parts)

	for _, segment := range segments {
		// Get the character before and after the user input
		charBeforeUserInput := ""
		if len(segment.CurrentSegment) > 0 {
			charBeforeUserInput = segment.CurrentSegment[len(segment.CurrentSegment)-1:]
		}

		charAfterUserInput := ""
		if len(segment.NextSegment) > 0 {
			charAfterUserInput = segment.NextSegment[:1]
		}

		// Check if the character before the user input is an escape character
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

		// Check if the character before and after the user input are the same
		if charBeforeUserInput != charAfterUserInput {
			return false
		}

		// Check if the user input contains the escape character itself
		if strings.Contains(userInput, charBeforeUserInput) {
			return false
		}

		// Check for dangerous characters inside double quotes
		// https://www.gnu.org/software/bash/manual/html_node/Single-Quotes.html
		// https://www.gnu.org/software/bash/manual/html_node/Double-Quotes.html
		if charBeforeUserInput == `"` {
			for _, dangerousChar := range dangerousCharsInsideDoubleQuotes {
				if strings.Contains(userInput, dangerousChar) {
					return false
				}
			}
		}
	}

	return true
}
