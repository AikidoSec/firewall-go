package sqlinjection

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsNotSQLInjection(t *testing.T) {
	require.NoError(t, internal.Init())

	tests := []struct {
		query string
		input string
	}{
		// It ignores invalid queries
		{"SELECT * FROM users WHERE id = 'users\\'", "users\\"},

		// It ignores safely escaped backslash
		{"SELECT * FROM users WHERE id = 'users\\\\'", "users\\\\"},

		// It allows escape sequences
		{"SELECT * FROM users WHERE id = '\nusers'", "\nusers"},
		{"SELECT * FROM users WHERE id = '\rusers'", "\rusers"},
		{"SELECT * FROM users WHERE id = '\tusers'", "\tusers"},

		// user input inside IN (...)
		{"SELECT * FROM users WHERE id IN ('123')", "'123'"},
		{"SELECT * FROM users WHERE id IN (123)", "123"},
		{"SELECT * FROM users WHERE id IN (123, 456)", "123"},
		{"SELECT * FROM users WHERE id IN (123, 456)", "456"},
		{"SELECT * FROM users WHERE id IN (13,14,15)", "13,14,15"},
		{"SELECT * FROM users WHERE id IN (13, 14, 154)", "13, 14, 154"},

		// It does not flag escaped # as SQL injection
		{"SELECT * FROM hashtags WHERE name = '#hashtag'", "#hashtag"},

		// It checks whether the string is safely escaped
		{"SELECT * FROM comments WHERE comment = 'I'm writing you'", "I'm writing you"},
		{"SELECT * FROM comments WHERE comment = \"I\"m writing you\"", "I\"m writing you"},
		{"SELECT * FROM comments WHERE comment = \"I'm writing you\"", "I'm writing you"},
		{"SELECT * FROM comments WHERE comment = 'I\"m writing you'", "I\"m writing you"},
		{"SELECT * FROM comments WHERE comment = \"I`m writing you\"", "I`m writing you"},

		// it does not flag queries starting with SELECT and having SELECT in user input
		{"SELECT * FROM users WHERE id = 1", "SELECT"},
		// input occurs in comment
		{"SELECT * FROM hashtags WHERE name = 'name' -- Query by name", "name"},

		{"SELECT * FROM users WHERE id = 'a\nb\nc';", "a\nb\nc"},

		// user input is longer than query
		{"SELECT * FROM users", "SELECT * FROM users WHERE id = 'a'"},

		// It flags multiline queries correctly
		{`
			SELECT * FROM users
			WHERE id = 123`, "123"},
		{`
			SELECT * FROM users
			WHERE id = '123'`, "123"},
		{`
			SELECT *
			FROM users
			WHERE is_escaped = "1' OR 1=1"`, "1' OR 1=1"},

		// It does not flag invalid function calls
		{"SELECT 'foobar)'", "foobar)"},
		{"SELECT 'foobar      )'", "foobar      )"},
		{"SELECT '€foobar()'", "€foobar()"},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			assert.False(t, detectSQLInjection(tt.query, tt.input, 0), "Expected no SQL injection")
		})
	}
}

func TestIsSQLInjection(t *testing.T) {
	require.NoError(t, internal.Init())

	tests := []struct {
		query string
		input string
	}{
		{"SELECT * FROM users WHERE id = '1' OR 1=1", "1' OR 1=1"},
		// It flags function calls as SQL injections
		{"SELECT foobar()", "foobar()"},
		{"SELECT foobar(1234567)", "foobar(1234567)"},
		{"SELECT 20+foobar()", "20+foobar()"},
		{"SELECT 20-foobar(", "20-foobar("},
		{"SELECT 20<foobar()", "20<foobar()"},
		{"SELECT 1foobar()", "1foobar()"},
		{"SELECT #foobar()", "#foobar()"},

		// Weird edge case, but we'll flag 'em as SQL injections for now
		// Requires better understanding of the SQL syntax
		{"SELECT * FROM hashtags WHERE name = '-- Query by name' -- Query by name", "-- Query by name"},

		// Test multiline comments flagged correctly :
		{`
			SELECT *
			FROM users
			WHERE id = '1' OR 1=1`, "1' OR 1=1"},
		{`
			SELECT *
			FROM users
			WHERE id = '1' OR 1=1
			AND is_escaped = '1'' OR 1=1'`, "1' OR 1=1"},
		{`
    		SELECT *
    		FROM users
    		WHERE id = '1' OR 1=1
        	AND is_escaped = "1' OR 1=1"`, "1' OR 1=1"},

		// it flags lowercased :
		{`
		  SELECT id,
				   email,
				   password_hash,
				   registered_at,
				   is_confirmed,
				   first_name,
				   last_name
			FROM users WHERE email_lowercase = '' or 1=1 -- a',`, "' OR 1=1 -- a"},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			assert.True(t, detectSQLInjection(tt.query, tt.input, 0), "Expected SQL injection detected")
		})
	}
}

func TestShouldReturnEarly(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		userInput string
		want      bool
	}{
		// Test cases where the function should return True
		{
			name:      "user input is empty",
			query:     "SELECT * FROM users",
			userInput: "",
			want:      true,
		},
		{
			name:      "user input is a single character",
			query:     "SELECT * FROM users",
			userInput: "a",
			want:      true,
		},
		{
			name:      "user input is larger than query",
			query:     "SELECT * FROM users",
			userInput: "SELECT * FROM users WHERE id = 1",
			want:      true,
		},
		{
			name:      "user input not in query",
			query:     "SELECT * FROM users",
			userInput: "DELETE",
			want:      true,
		},
		{
			name:      "user input is alphanumerical - users123",
			query:     "SELECT * FROM users123",
			userInput: "users123",
			want:      true,
		},
		{
			name:      "user input is alphanumerical - users_123",
			query:     "SELECT * FROM users_123",
			userInput: "users_123",
			want:      true,
		},
		{
			name:      "user input is alphanumerical - __1",
			query:     "SELECT __1 FROM users_123",
			userInput: "__1",
			want:      true,
		},
		{
			name:      "user input is alphanumerical - long table name",
			query:     "SELECT * FROM table_name_is_fun_12",
			userInput: "table_name_is_fun_12",
			want:      true,
		},
		{
			name:      "user input is a valid comma-separated number list",
			query:     "SELECT * FROM users",
			userInput: "1,2,3",
			want:      true,
		},
		{
			name:      "user input is a valid number",
			query:     "SELECT * FROM users",
			userInput: "123",
			want:      true,
		},
		{
			name:      "user input is a valid number with spaces",
			query:     "SELECT * FROM users",
			userInput: "  123  ",
			want:      true,
		},
		{
			name:      "user input is a valid number with commas and spaces",
			query:     "SELECT * FROM users",
			userInput: "1, 2, 3",
			want:      true,
		},
		// Test cases where the function should return False
		{
			name:      "user input is in query",
			query:     "SELECT * FROM users",
			userInput: " users",
			want:      false,
		},
		{
			name:      "user input is a valid string in query",
			query:     "SELECT * FROM users",
			userInput: "SELECT ",
			want:      false,
		},
		{
			name:      "user input is a valid string in query with special characters",
			query:     "SELECT * FROM users; DROP TABLE",
			userInput: "users; DROP TABLE",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldReturnEarly(tt.query, tt.userInput)
			assert.Equal(t, tt.want, got)
		})
	}
}

func BenchmarkDetectSQLInjection(b *testing.B) {
	tests := getBenchmarkTests()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			for _, tt := range tests {
				detectSQLInjection(tt.query, tt.input, 0)
			}
		}
	})
}

func getBenchmarkTests() []struct {
	query string
	input string
} {
	return []struct {
		query string
		input string
	}{
		{"SELECT * FROM users WHERE id = 'users\\'", "users\\"},
		{"SELECT * FROM users WHERE id IN (13, 14, 154)", "13, 14, 154"},
		{"SELECT * FROM hashtags WHERE name = '#hashtag'", "#hashtag"},
		{"SELECT * FROM comments WHERE comment = 'I'm writing you'", "I'm writing you"},
		{"SELECT * FROM users WHERE id = 1", "SELECT"},
		{"SELECT * FROM hashtags WHERE name = 'name' -- Query by name", "name"},
		{"SELECT * FROM users WHERE id = 'a\nb\nc';", "a\nb\nc"},
		{"SELECT * FROM users", "SELECT * FROM users WHERE id = 'a'"},
		{`
		SELECT * FROM users
		WHERE id = 123`, "123"},

		{"SELECT 'foobar      )'", "foobar      )"},
		{"SELECT * FROM users WHERE id = '1' OR 1=1", "1' OR 1=1"},
		{"SELECT foobar()", "foobar()"},
		{"SELECT foobar(1234567)", "foobar(1234567)"},
		{"SELECT 20-foobar(", "20-foobar("},
		{"SELECT 20<foobar()", "20<foobar()"},
		{"SELECT * FROM hashtags WHERE name = '-- Query by name' -- Query by name", "-- Query by name"},
		{`
		SELECT *
		FROM users
		WHERE id = '1' OR 1=1`, "1' OR 1=1"},
		{`
	  SELECT id,
			   email,
			   password_hash,
			   registered_at,
			   is_confirmed,
			   first_name,
			   last_name
		FROM users WHERE email_lowercase = '' or 1=1 -- a',`, "' OR 1=1 -- a"},
	}
}
