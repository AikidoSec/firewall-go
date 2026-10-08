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
	commandSubstitution // Inside $(...) or `...`
)

// quoteStatesAt returns the quote context active just before each byte of
// command, plus one trailing entry for the context once the string ends.
func quoteStatesAt(command string) []quoteContext {
	states := make([]quoteContext, len(command)+1)

	// Stack to track nested contexts (quotes and command substitutions)
	type contextFrame struct {
		ctx   quoteContext
		depth int // For tracking $( ) nesting depth
	}
	stack := []contextFrame{{ctx: noQuote, depth: 0}}

	escaped := false

	for i := 0; i < len(command); i++ {
		current := stack[len(stack)-1]
		states[i] = current.ctx
		ch := command[i]

		if escaped {
			escaped = false
			continue
		}

		if ch == '\\' {
			if current.ctx != singleQuote {
				escaped = true
			}
			continue
		}

		switch current.ctx {
		case singleQuote:
			// Inside single quotes, only ' ends the quote
			if ch == '\'' {
				stack = stack[:len(stack)-1]
			}

		case doubleQuote:
			switch ch {
			case '"':
				// End double quote
				stack = stack[:len(stack)-1]
			case '`':
				// Backtick command substitution inside double quotes
				stack = append(stack, contextFrame{ctx: commandSubstitution, depth: 0})
			case '$':
				// Check for $( command substitution
				if i+1 < len(command) && command[i+1] == '(' {
					stack = append(stack, contextFrame{ctx: commandSubstitution, depth: 1})
					i++ // Skip the '('
					states[i] = commandSubstitution
				}
			}

		case commandSubstitution:
			switch ch {
			case '\'':
				// Single quote inside command substitution
				stack = append(stack, contextFrame{ctx: singleQuote, depth: 0})
			case '"':
				// Double quote inside command substitution
				stack = append(stack, contextFrame{ctx: doubleQuote, depth: 0})
			case '`':
				// End backtick command substitution (if we're in backtick mode)
				if current.depth == 0 {
					stack = stack[:len(stack)-1]
				} else {
					// Nested backtick inside $() - start new backtick substitution
					stack = append(stack, contextFrame{ctx: commandSubstitution, depth: 0})
				}
			case '$':
				// Check for nested $( command substitution
				if i+1 < len(command) && command[i+1] == '(' {
					stack = append(stack, contextFrame{ctx: commandSubstitution, depth: 1})
					i++ // Skip the '('
					states[i] = commandSubstitution
				}
			case '(':
				// Track parenthesis depth for $() substitutions
				if current.depth > 0 {
					stack[len(stack)-1].depth++
				}
			case ')':
				// End $() command substitution or decrease depth
				if current.depth > 0 {
					if current.depth == 1 {
						stack = stack[:len(stack)-1]
					} else {
						stack[len(stack)-1].depth--
					}
				}
			}

		case noQuote:
			switch ch {
			case '\'':
				stack = append(stack, contextFrame{ctx: singleQuote, depth: 0})
			case '"':
				stack = append(stack, contextFrame{ctx: doubleQuote, depth: 0})
			case '`':
				stack = append(stack, contextFrame{ctx: commandSubstitution, depth: 0})
			case '$':
				// Check for $( command substitution
				if i+1 < len(command) && command[i+1] == '(' {
					stack = append(stack, contextFrame{ctx: commandSubstitution, depth: 1})
					i++ // Skip the '('
					states[i] = commandSubstitution
				}
			}
		}
	}

	// Final state
	if len(stack) > 0 {
		states[len(command)] = stack[len(stack)-1].ctx
	} else {
		states[len(command)] = noQuote
	}
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
		case commandSubstitution:
			// Inside command substitutions, user input is NOT safely encapsulated
			// because shell metacharacters and separators are active
			return false
		}
		if strings.ContainsAny(userInput, breakoutChars) {
			return false
		}
		if !quoteClosesAfter(states, occEnd, context) {
			return false
		}
	}
}
