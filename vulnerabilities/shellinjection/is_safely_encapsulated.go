package shellinjection

import (
	"strings"
)

// quoteContext represents the quoting state at a position in the command.
type quoteContext int

const (
	noQuote quoteContext = iota
	singleQuote
	doubleQuote
)

// quoteStatesAt returns the quote context active just before each byte of
// command, plus one trailing entry for the context once the string ends.
func quoteStatesAt(command string) []quoteContext {
	states := make([]quoteContext, len(command)+1)
	context := noQuote
	escaped := false

	for i := 0; i < len(command); i++ {
		states[i] = context
		ch := command[i]

		if escaped {
			escaped = false
			continue
		}

		if ch == '\\' {
			if context != singleQuote {
				escaped = true
			}
			continue
		}

		switch ch {
		case '\'':
			switch context {
			case noQuote:
				context = singleQuote
			case singleQuote:
				context = noQuote
			}
			// Inside double quotes, single quote is literal
		case '"':
			switch context {
			case noQuote:
				context = doubleQuote
			case doubleQuote:
				context = noQuote
			}
			// Inside single quotes, double quote is literal
		}
	}

	states[len(command)] = context
	return states
}

// quoteClosesAfter reports whether context is exited again at or after
// position start. An unterminated quote must not be treated as safe.
func quoteClosesAfter(states []quoteContext, start int, context quoteContext) bool {
	for _, state := range states[start:] {
		if state != context {
			return true
		}
	}
	return false
}

func isSafelyEncapsulated(command, userInput string) bool {
	if userInput == "" {
		return true
	}
	states := quoteStatesAt(command)

	for start := 0; ; {
		idx := strings.Index(command[start:], userInput)
		if idx == -1 {
			return true
		}
		occStart := start + idx
		occEnd := occStart + len(userInput)
		start = occEnd

		context := states[occStart]
		// Characters in userInput that would break out of the surrounding quote.
		var breakoutChars string
		switch context {
		case noQuote:
			return false
		case singleQuote:
			breakoutChars = "'"
		case doubleQuote:
			// https://www.gnu.org/software/bash/manual/html_node/Double-Quotes.html
			breakoutChars = "$`\\!\""
		}
		if strings.ContainsAny(userInput, breakoutChars) {
			return false
		}
		if !quoteClosesAfter(states, occEnd, context) {
			return false
		}
	}
}
