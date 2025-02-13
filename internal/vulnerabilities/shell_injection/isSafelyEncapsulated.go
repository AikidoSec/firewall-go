package shell_injection

import (
	"github.com/AikidoSec/firewall-go/internal/helpers"
	"strings"
)

var escapeChars = []string{`"`, `'`}
var dangerousCharsInsideDoubleQuotes = []string{"$", "`", "\\", "!"}

func isSafelyEncapsulated(command, userInput string) bool {
	segments := helpers.GetCurrentAndNextSegments(strings.Split(command, userInput))

	for _, segment := range segments {
		currentSegment := segment.CurrentSegment
		nextSegment := segment.NextSegment

		// Get the character before and after the user input
		charBeforeUserInput := ""
		if len(currentSegment) > 0 {
			charBeforeUserInput = currentSegment[len(currentSegment)-1:]
		}

		charAfterUserInput := ""
		if len(nextSegment) > 0 {
			charAfterUserInput = nextSegment[:1]
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
