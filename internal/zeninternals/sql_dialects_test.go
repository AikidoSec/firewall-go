package zeninternals

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetSQLDialectFromString(t *testing.T) {
	require.Equal(t, int(MySQL), GetSQLDialectFromString("mysql"))
	require.Equal(t, int(SQLite), GetSQLDialectFromString("sqlite"))
	require.Equal(t, int(PostgreSQL), GetSQLDialectFromString("postgres"))
	require.Equal(t, int(Generic), GetSQLDialectFromString("unknown"))
}
