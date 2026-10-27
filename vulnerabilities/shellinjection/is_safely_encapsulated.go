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

type quoteState struct {
	context quoteContext
	quoteID int
}

type shellContext struct {
	quoteState
	terminator  byte
	parentheses int
}

// quoteStatesAt tracks quotes independently inside command substitutions.
// Each quote gets its own closing position, so an outer quote cannot close an
// unterminated quote inside a substitution.
func quoteStatesAt(command string) ([]quoteState, []int) {
	states := make([]quoteState, len(command)+1)
	quoteEnds := []int{-1}
	contexts := []shellContext{{}}

	for i := 0; i < len(command); i++ {
		current := &contexts[len(contexts)-1]
		states[i] = current.quoteState
		ch := command[i]

		// Backtick delimiters are processed before the enclosed command's
		// quotes, unlike the closing parenthesis of a $(...) substitution.
		if ch == '`' && current.terminator == '`' {
			contexts = contexts[:len(contexts)-1]
			continue
		}

		if ch == '\\' && i+1 < len(command) {
			next := command[i+1]
			escapes := current.context == noQuote ||
				(current.context == doubleQuote && strings.ContainsRune("$`\"\\\n", rune(next))) ||
				(current.terminator == '`' && strings.ContainsRune("$`\\\n", rune(next)))
			if escapes {
				i++
				states[i] = current.quoteState
				continue
			}
		}

		if current.context != singleQuote && ch == '$' && i+1 < len(command) && command[i+1] == '(' {
			i++
			states[i] = current.quoteState
			contexts = append(contexts, shellContext{terminator: ')'})
			continue
		}
		if current.context != singleQuote && ch == '`' {
			contexts = append(contexts, shellContext{terminator: '`'})
			continue
		}
		if current.context == noQuote && current.terminator == ')' {
			switch ch {
			case '(':
				current.parentheses++
			case ')':
				if current.parentheses == 0 {
					contexts = contexts[:len(contexts)-1]
				} else {
					current.parentheses--
				}
				continue
			}
		}

		var quote quoteContext
		switch ch {
		case '\'':
			quote = singleQuote
		case '"':
			quote = doubleQuote
		default:
			continue
		}
		switch current.context {
		case noQuote:
			current.context = quote
			current.quoteID = len(quoteEnds)
			quoteEnds = append(quoteEnds, -1)
		case quote:
			quoteEnds[current.quoteID] = i
			current.quoteState = quoteState{}
		}
	}

	states[len(command)] = contexts[len(contexts)-1].quoteState
	return states, quoteEnds
}

// quoteClosesAfter checks the closing delimiter of this specific quote.
func quoteClosesAfter(quoteEnds []int, start int, state quoteState) bool {
	return quoteEnds[state.quoteID] >= start
}

func isSafelyEncapsulated(command, userInput string) bool {
	if userInput == "" {
		return true
	}
	states, quoteEnds := quoteStatesAt(command)

	for start := 0; ; {
		idx := strings.Index(command[start:], userInput)
		if idx == -1 {
			return true
		}
		occStart := start + idx
		occEnd := occStart + len(userInput)
		start = occEnd

		state := states[occStart]
		// Characters in userInput that would break out of the surrounding quote.
		var breakoutChars string
		switch state.context {
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
		if !quoteClosesAfter(quoteEnds, occEnd, state) {
			return false
		}
	}
}
