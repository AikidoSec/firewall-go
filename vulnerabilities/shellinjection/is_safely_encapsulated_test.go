package shellinjection

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSafelyEncapsulated(t *testing.T) {
	t.Run("safe between single quotes", func(t *testing.T) {
		assert.True(t, isSafelyEncapsulated("echo '$USER'", "$USER"))
		assert.True(t, isSafelyEncapsulated("echo '`$USER'", "`USER"))
	})

	t.Run("single quote in single quotes", func(t *testing.T) {
		assert.False(t, isSafelyEncapsulated("echo ''USER'", "'USER"))
	})

	t.Run("dangerous chars between double quotes", func(t *testing.T) {
		assert.True(t, isSafelyEncapsulated(`echo "=USER"`, "=USER"))
		assert.False(t, isSafelyEncapsulated(`echo "$USER"`, "$USER"))
		assert.False(t, isSafelyEncapsulated(`echo "!USER"`, "!USER"))
		assert.False(t, isSafelyEncapsulated("echo \"`USER\"", "`USER"))
		assert.False(t, isSafelyEncapsulated(`echo "\\USER"`, "\\USER"))
	})

	t.Run("same user input multiple times", func(t *testing.T) {
		assert.True(t, isSafelyEncapsulated(`echo '$USER' '$USER'`, "$USER"))
		assert.False(t, isSafelyEncapsulated(`echo "$USER" '$USER'`, "$USER"))
		assert.False(t, isSafelyEncapsulated(`echo "$USER" "$USER"`, "$USER"))
	})

	t.Run("the first and last quote doesn't match", func(t *testing.T) {
		assert.False(t, isSafelyEncapsulated(`echo '$USER"`, "$USER"))
		assert.False(t, isSafelyEncapsulated(`echo "$USER'`, "$USER"))
	})

	t.Run("the first or last character is not an escape char", func(t *testing.T) {
		assert.False(t, isSafelyEncapsulated(`echo $USER'`, "$USER"))
		assert.False(t, isSafelyEncapsulated(`echo $USER"`, "$USER"))
	})

	t.Run("user input does not occur in the command", func(t *testing.T) {
		assert.True(t, isSafelyEncapsulated(`echo 'USER'`, "$USER"))
		assert.True(t, isSafelyEncapsulated(`echo "USER"`, "$USER"))
	})

	t.Run("empty user input", func(t *testing.T) {
		assert.True(t, isSafelyEncapsulated("echo hello", ""))
	})

	t.Run("empty user input", func(t *testing.T) {
		if got := isSafelyEncapsulated("echo hello", ""); got != true {
			t.Errorf("isSafelyEncapsulated('echo hello', '') = %v; want true", got)
		}
	})
}

func TestIsSafelyEncapsulated_NestedQuoting(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		userInput string
		expected  bool
	}{
		{
			name:      "safe inside single quotes",
			command:   `echo '$USER'`,
			userInput: "$USER",
			expected:  true,
		},
		{
			name:      "unquoted is unsafe",
			command:   `echo $USER`,
			userInput: "$USER",
			expected:  false,
		},
		{
			name:      "dangerous char inside double quotes is unsafe",
			command:   `echo "$USER"`,
			userInput: "$USER",
			expected:  false,
		},
		{
			name:      "user input not present is safe",
			command:   `echo 'USER'`,
			userInput: "$USER",
			expected:  true,
		},
		// Nested quoting bypass: single quotes are literal inside double
		// quotes, so they don't stop command/variable substitution.
		{
			name:      "command substitution nested in single-in-double quotes",
			command:   `echo "'$(id)'"`,
			userInput: "$(id)",
			expected:  false,
		},
		{
			name:      "variable expansion nested in single-in-double quotes",
			command:   `echo "'$USER'"`,
			userInput: "$USER",
			expected:  false,
		},
		{
			name:      "backtick command substitution nested in single-in-double quotes",
			command:   "echo \"'`id`'\"",
			userInput: "`id`",
			expected:  false,
		},
		{
			name:      "triple nested single quotes inside double quotes",
			command:   `echo "'''$(id)'''"`,
			userInput: "$(id)",
			expected:  false,
		},
		{
			name:      "escaped double quotes still count as double-quote context",
			command:   `echo "\"'$(id)'\""`,
			userInput: "$(id)",
			expected:  false,
		},
		// The reverse nesting is genuinely safe: double quotes are literal
		// inside single quotes.
		{
			name:      "double quotes nested inside single quotes stay safe",
			command:   `echo '"$USER"'`,
			userInput: "$USER",
			expected:  true,
		},
		{
			name:      "double quotes with backtick nested inside single quotes stay safe",
			command:   "echo '\"`id`\"'",
			userInput: "`id`",
			expected:  true,
		},
		// Malformed/unterminated quoting must not be reported safe just
		// because the last-seen quote type happened to be single or double.
		{
			name:      "unterminated single quote before double quote is unsafe",
			command:   `echo '$USER"`,
			userInput: "$USER",
			expected:  false,
		},
		{
			name:      "unterminated double quote before single quote is unsafe",
			command:   `echo "$USER'`,
			userInput: "$USER",
			expected:  false,
		},
		// Multiple occurrences: all must be safe for the whole thing to be safe.
		{
			name:      "same input safe in both occurrences",
			command:   `echo '$USER' '$USER'`,
			userInput: "$USER",
			expected:  true,
		},
		{
			name:      "one unsafe occurrence makes the whole thing unsafe",
			command:   `echo "$USER" '$USER'`,
			userInput: "$USER",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSafelyEncapsulated(tt.command, tt.userInput)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// Hand-picked expected values can all pass while still diverging from real shell behavior.
func TestIsSafelyEncapsulated_DifferentialAgainstRealBash(t *testing.T) {
	marker := `$(id)`

	templates := []string{
		"echo %s",
		"echo '%s'",
		"echo \"%s\"",
		"echo \"'%s'\"",
		"echo '\"%s\"'",
		"echo \"\\\"'%s'\\\"\"",
		"echo \"'''%s'''\"",
		"echo '\"\"\"%s\"\"\"'",
		"echo \"a\\\\\\\"'%s'\\\"\"",
		"echo \"a\\\\\\\\\"'%s'",
		"echo '%s' \"%s\"",
		"echo \"%s\" '%s'",
		"echo \"pre'mid%spost'end\"",
		"echo 'pre\"mid%spost\"end'",
		"echo \"a'b'%s'c'd\"",
		"echo '\\''%s'\\''",
		"echo \"\\$%s\"",
		"echo \"%s\\\\\"",
		"echo '%s\"",
		"echo \"%s'",
	}

	for _, tmpl := range templates {
		t.Run(tmpl, func(t *testing.T) {
			var command string
			if strings.Count(tmpl, "%s") == 2 {
				command = fmt.Sprintf(tmpl, marker, marker)
			} else {
				command = fmt.Sprintf(tmpl, marker)
			}

			verdict := isSafelyEncapsulated(command, marker)

			out, _ := exec.Command("sh", "-c", command).CombinedOutput()
			executed := strings.Contains(string(out), "uid=")

			assert.False(t, verdict && executed,
				"bypass: verdict=safe but real sh executed the payload. command=%q output=%q", command, string(out))
		})
	}
}
