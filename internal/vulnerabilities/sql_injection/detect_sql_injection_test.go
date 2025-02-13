package sql_injection

import (
	"github.com/AikidoSec/firewall-go/internal"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIsNotSqlInjection(t *testing.T) {
	internal.Init()
	tests := []struct {
		query string
		input string
	}{
		{"SELECT * FROM users WHERE id = 'users\\'", "users\\"},
		{"SELECT * FROM users WHERE id = 'users\\\\'", "users\\\\"},
		{"SELECT * FROM users WHERE id = '\nusers'", "\nusers"},
		{"SELECT * FROM users WHERE id = '\rusers'", "\rusers"},
		{"SELECT * FROM users WHERE id = '\tusers'", "\tusers"},
		{"SELECT * FROM users WHERE id IN ('123')", "'123'"},
		{"SELECT * FROM users WHERE id IN (123)", "123"},
		{"SELECT * FROM users WHERE id IN (123, 456)", "123"},
		{"SELECT * FROM users WHERE id IN (123, 456)", "456"},
		{"SELECT * FROM users WHERE id IN (13,14,15)", "13,14,15"},
		{"SELECT * FROM users WHERE id IN (13, 14, 154)", "13, 14, 154"},
		{"SELECT * FROM hashtags WHERE name = '#hashtag'", "#hashtag"},
		{"SELECT * FROM comments WHERE comment = 'I\"m writting you'", "I'm writting you"},
		{"SELECT * FROM comments WHERE comment = 'I\"m writting you'", "I\"m writting you"},
		{"SELECT * FROM users WHERE id = 1", "SELECT"},
		{"SELECT * FROM hashtags WHERE name = '-- Query by name' -- Query by name", "-- Query by name"},
		{"SELECT * FROM hashtags WHERE name = 'name' -- Query by name", "name"},
		{"SELECT * FROM users WHERE id = 'a\nb\nc';", "a\nb\nc"},
		{"SELECT * FROM users", "SELECT * FROM users WHERE id = 'a'"},
		{"SELECT * FROM users WHERE id = 123", "123"},
		{"SELECT * FROM users WHERE id = '123'", "123"},
		{"SELECT * FROM users WHERE is_escaped = '1' OR 1=1", "1' OR 1=1"},
		{"SELECT groups.id AS group_id, group_settings.user_id, group_settings.settings FROM groups INNER JOIN group_settings ON groups.id = group_settings.group_id AND group_settings.user_id = ? WHERE groups.business_id = ? GROUP BY group_id ORDER BY group_id DESC, group_settings.user_id ASC", "group_id"},
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
		{"SELECT foobar()", "foobar()"},
		{"SELECT foobar(1234567)", "foobar(1234567)"},
		{"SELECT 20+foobar()", "20+foobar()"},
		{"SELECT 20-foobar(", "20-foobar("},
		{"SELECT 20<foobar()", "20<foobar()"},
		{"SELECT 1foobar()", "1foobar()"},
		{"SELECT #foobar()", "#foobar()"},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			assert.True(t, detectSQLInjection(tt.query, tt.input, 0), "Expected SQL injection detected")
		})
	}
}
