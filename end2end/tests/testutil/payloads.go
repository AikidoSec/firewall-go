package testutil

import "os"

func AppSQLDialect() string {
	return os.Getenv("APP_SQL_DIALECT")
}

var DialectPayloads = map[string]string{
	"postgres": "Fluffy' || current_user || '",
	"mysql":    "Fluffy', 'x') #",
}
