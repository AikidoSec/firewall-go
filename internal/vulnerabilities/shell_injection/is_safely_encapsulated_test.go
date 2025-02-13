package shell_injection

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIsSafelyEncapsulated(t *testing.T) {
	assert := assert.New(t)

	// Safe between single quotes
	assert.Equal(isSafelyEncapsulated("echo '$USER'", "$USER"), true)
	assert.Equal(isSafelyEncapsulated("echo '`$USER'", "`USER"), true)

	// Single quote in single quotes
	assert.Equal(isSafelyEncapsulated("echo ''USER'", "'USER"), false)

	// Dangerous chars between double quotes
	assert.Equal(isSafelyEncapsulated(`echo "=USER"`, "=USER"), true)
	assert.Equal(isSafelyEncapsulated(`echo "$USER"`, "$USER"), false)
	assert.Equal(isSafelyEncapsulated(`echo "!USER"`, "!USER"), false)
	assert.Equal(isSafelyEncapsulated(`echo "\\USER"`, "\\USER"), false)

	// Same user input multiple times
	assert.Equal(isSafelyEncapsulated(`echo '$USER' '$USER'`, "$USER"), true)
	assert.Equal(isSafelyEncapsulated(`echo "$USER" '$USER'`, "$USER"), false)
	assert.Equal(isSafelyEncapsulated(`echo "$USER" "$USER"`, "$USER"), false)

	// The first and last quote doesn't match
	assert.Equal(isSafelyEncapsulated(`echo '$USER"`, "$USER"), false)
	assert.Equal(isSafelyEncapsulated(`echo "$USER'`, "$USER"), false)

	// The first or last character is not an escape char
	assert.Equal(isSafelyEncapsulated(`echo $USER'`, "$USER"), false)
	assert.Equal(isSafelyEncapsulated(`echo $USER"`, "$USER"), false)

	// User input does not occur in the command
	assert.Equal(isSafelyEncapsulated(`echo 'USER'`, "$USER"), true)
	assert.Equal(isSafelyEncapsulated(`echo "USER"`, "$USER"), true)
}
