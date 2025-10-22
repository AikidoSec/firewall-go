package sqlinjection

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal"
	"github.com/stretchr/testify/assert"
)

func TestIsNotSqlInjection(t *testing.T) {
	internal.Init()
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

func TestIsSqlInjection(t *testing.T) {
	internal.Init()
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

func BenchmarkDetectSQLInjectionDylib(b *testing.B) {
	tests := getBenchmarkTests()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			for _, tt := range tests {
				detectSQLInjection(tt.query, tt.input, 0)
			}
		}
	})
}

func BenchmarkDetectSQLInjectionWASM(b *testing.B) {
	tests := getBenchmarkTests()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			for _, tt := range tests {
				detectSQLInjectionWASM(tt.query, tt.input, 0)
			}
		}
	})
}
