package shellinjection

import (
	"testing"
)

func TestContainsShellSyntax(t *testing.T) {
	// Helper function for checking containsShellSyntax
	containsSyntax := func(str string, expected bool) {
		if result := containsShellSyntax(str, str); result != expected {
			t.Errorf("Expected %v for input '%s', but got %v", expected, str, result)
		}
	}

	t.Run("it detects shell syntax", func(t *testing.T) {
		containsSyntax("", false)
		containsSyntax("hello", false)
		containsSyntax("\n", false)
		containsSyntax("\n\n", false)

		containsSyntax("$(command)", true)
		containsSyntax("$(command arg arg)", true)
		containsSyntax("`command`", true)
		containsSyntax("\narg", true)
		containsSyntax("\targ", true)
		containsSyntax("\narg\n", true)
		containsSyntax("arg\n", true)
		containsSyntax("arg\narg", true)
		containsSyntax("rm -rf", true)
		containsSyntax("/bin/rm -rf", true)
		containsSyntax("/bin/rm", true)
		containsSyntax("/sbin/sleep", true)
		containsSyntax("/usr/bin/kill", true)
		containsSyntax("/usr/bin/killall", true)
		containsSyntax("/usr/bin/env", true)
		containsSyntax("/bin/ps", true)
		containsSyntax("/usr/bin/W", true)
	})

	t.Run("it detects commands surrounded by separators", func(t *testing.T) {
		expected := true
		result := containsShellSyntax(`find /path/to/search -type f -name "pattern" -exec rm {} \\;`, "rm")
		if result != expected {
			t.Errorf("Expected %v for 'rm' in command, but got %v", expected, result)
		}
	})

	t.Run("it detects commands with separator before", func(t *testing.T) {
		expected := true
		result := containsShellSyntax(`find /path/to/search -type f -name "pattern" | xargs rm`, "rm")
		if result != expected {
			t.Errorf("Expected %v for 'rm' in command, but got %v", expected, result)
		}
	})

	t.Run("it detects commands with separator after", func(t *testing.T) {
		expected := true
		result := containsShellSyntax("rm arg", "rm")
		if result != expected {
			t.Errorf("Expected %v for 'rm' in command, but got %v", expected, result)
		}
	})

	t.Run("it checks if the same command occurs in the user input", func(t *testing.T) {
		expected := false
		result := containsShellSyntax("find cp", "rm")
		if result != expected {
			t.Errorf("Expected %v for 'rm' in command, but got %v", expected, result)
		}
	})

	t.Run("it treats colon as a command", func(t *testing.T) {
		expected := true
		result := containsShellSyntax(":|echo", ":|")
		if result != expected {
			t.Errorf("Expected %v for ':|' in command, but got %v", expected, result)
		}

		expected = false
		result = containsShellSyntax("https://www.google.com", "https://www.google.com")
		if result != expected {
			t.Errorf("Expected %v for 'https://www.google.com' in command, but got %v", expected, result)
		}
	})

	t.Run("it flags input as shell injection", func(t *testing.T) {
		expected := true
		result := containsShellSyntax("command -disable-update-check -target https://examplx.com|curl+https://cde-123.abc.domain.com+%23 -json-export /tmp/5891/8526757.json -tags microsoft,windows,exchange,iis,gitlab,oracle,cisco,joomla -stats -stats-interval 3 -retries 3 -no-stdin", "https://examplx.com|curl+https://cde-123.abc.domain.com+%23")
		if result != expected {
			t.Errorf("Expected %v for shell injection detection, but got %v", expected, result)
		}
	})

	t.Run("it detects carriage return as separator", func(t *testing.T) {
		checkSep := func(str, cmd string) {
			if !containsShellSyntax(str, cmd) {
				t.Errorf("Expected shell syntax detected in %q for command %q", str, cmd)
			}
		}
		checkSep("ls\rrm", "rm")
		checkSep("echo test\rrm -rf /", "rm")
		checkSep("rm\rls", "rm")
	})

	t.Run("it detects form feed as separator", func(t *testing.T) {
		checkSep := func(str, cmd string) {
			if !containsShellSyntax(str, cmd) {
				t.Errorf("Expected shell syntax detected in %q for command %q", str, cmd)
			}
		}
		checkSep("ls\frm", "rm")
		checkSep("echo test\frm -rf /", "rm")
		checkSep("rm\fls", "rm")
	})
}
