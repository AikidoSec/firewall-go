package shellinjection

import (
	"testing"
)

func TestIsSafelyEncapsulated(t *testing.T) {
	t.Run("safe between single quotes", func(t *testing.T) {
		if got := isSafelyEncapsulated("echo '$USER'", "$USER"); got != true {
			t.Errorf("isSafelyEncapsulated('echo '$USER'', '$USER') = %v; want true", got)
		}
		if got := isSafelyEncapsulated("echo '`$USER'", "`USER"); got != true {
			t.Errorf("isSafelyEncapsulated('echo '`$USER'', '`USER') = %v; want true", got)
		}
	})

	t.Run("single quote in single quotes", func(t *testing.T) {
		if got := isSafelyEncapsulated("echo ''USER'", "'USER"); got != false {
			t.Errorf("isSafelyEncapsulated('echo ''USER'', ''USER') = %v; want false", got)
		}
	})

	t.Run("dangerous chars between double quotes", func(t *testing.T) {
		if got := isSafelyEncapsulated(`echo "=USER"`, "=USER"); got != true {
			t.Errorf("isSafelyEncapsulated('echo \"=USER\"', '=USER') = %v; want true", got)
		}
		if got := isSafelyEncapsulated(`echo "$USER"`, "$USER"); got != false {
			t.Errorf("isSafelyEncapsulated('echo \"$USER\"', '$USER') = %v; want false", got)
		}
		if got := isSafelyEncapsulated(`echo "!USER"`, "!USER"); got != false {
			t.Errorf("isSafelyEncapsulated('echo \"!USER\"', '!USER') = %v; want false", got)
		}
		if got := isSafelyEncapsulated("echo \"`USER\"", "`USER"); got != false {
			t.Errorf("isSafelyEncapsulated('echo \"\\`USER\"', '`USER') = %v; want false", got)
		}
		if got := isSafelyEncapsulated(`echo "\\USER"`, "\\USER"); got != false {
			t.Errorf("isSafelyEncapsulated('echo \"\\\\USER\"', '\\USER') = %v; want false", got)
		}
	})

	t.Run("same user input multiple times", func(t *testing.T) {
		if got := isSafelyEncapsulated(`echo '$USER' '$USER'`, "$USER"); got != true {
			t.Errorf("isSafelyEncapsulated('echo '$USER' '$USER'', '$USER') = %v; want true", got)
		}
		if got := isSafelyEncapsulated(`echo "$USER" '$USER'`, "$USER"); got != false {
			t.Errorf("isSafelyEncapsulated('echo \"$USER\" '$USER'', '$USER') = %v; want false", got)
		}
		if got := isSafelyEncapsulated(`echo "$USER" "$USER"`, "$USER"); got != false {
			t.Errorf("isSafelyEncapsulated('echo \"$USER\" \"$USER\"', '$USER') = %v; want false", got)
		}
	})

	t.Run("the first and last quote doesn't match", func(t *testing.T) {
		if got := isSafelyEncapsulated(`echo '$USER"`, "$USER"); got != false {
			t.Errorf("isSafelyEncapsulated('echo '$USER\"', '$USER') = %v; want false", got)
		}
		if got := isSafelyEncapsulated(`echo "$USER'`, "$USER"); got != false {
			t.Errorf("isSafelyEncapsulated('echo \"$USER'\", '$USER') = %v; want false", got)
		}
	})

	t.Run("the first or last character is not an escape char", func(t *testing.T) {
		if got := isSafelyEncapsulated(`echo $USER'`, "$USER"); got != false {
			t.Errorf("isSafelyEncapsulated('echo $USER'', '$USER') = %v; want false", got)
		}
		if got := isSafelyEncapsulated(`echo $USER"`, "$USER"); got != false {
			t.Errorf("isSafelyEncapsulated('echo $USER\"', '$USER') = %v; want false", got)
		}
	})

	t.Run("user input does not occur in the command", func(t *testing.T) {
		if got := isSafelyEncapsulated(`echo 'USER'`, "$USER"); got != true {
			t.Errorf("isSafelyEncapsulated('echo 'USER'', '$USER') = %v; want true", got)
		}
		if got := isSafelyEncapsulated(`echo "USER"`, "$USER"); got != true {
			t.Errorf("isSafelyEncapsulated('echo \"USER\"', '$USER') = %v; want true", got)
		}
	})

	t.Run("nested quoting - single quotes inside double quotes", func(t *testing.T) {
		// This is the vulnerability case: echo "'$(id)'"
		// The $(id) appears between literal single quotes, but those are inside double quotes
		// so command substitution is still active
		if got := isSafelyEncapsulated(`echo "'$(id)'"`, "$(id)"); got != false {
			t.Errorf("isSafelyEncapsulated('echo \"'$(id)'\"', '$(id)') = %v; want false", got)
		}
		if got := isSafelyEncapsulated(`echo "'$USER'"`, "$USER"); got != false {
			t.Errorf("isSafelyEncapsulated('echo \"'$USER'\"', '$USER') = %v; want false", got)
		}
		if got := isSafelyEncapsulated(`echo "'\`id\`'"`, "`id`"); got != false {
			t.Errorf("isSafelyEncapsulated('echo \"'\\`id\\`'\"', '`id`') = %v; want false", got)
		}
	})

	t.Run("nested quoting - double quotes inside single quotes", func(t *testing.T) {
		// Double quotes inside single quotes are literal, so this is safe
		if got := isSafelyEncapsulated(`echo '"$USER"'`, "$USER"); got != true {
			t.Errorf("isSafelyEncapsulated('echo '\"$USER\"'', '$USER') = %v; want true", got)
		}
		if got := isSafelyEncapsulated(`echo '"\`id\`"'`, "`id`"); got != true {
			t.Errorf("isSafelyEncapsulated('echo '\"\\`id\\`\"'', '`id`') = %v; want true", got)
		}
	})
}
