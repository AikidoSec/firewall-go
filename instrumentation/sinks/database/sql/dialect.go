package sql

import (
	"database/sql/driver"
	"reflect"
	"strings"
)

// GetDialectFromDriver determines the SQL dialect by inspecting the driver type.
func GetDialectFromDriver(d driver.Driver) string {
	if d == nil {
		return "generic"
	}
	return resolveDialectFromDriverType(reflect.TypeOf(d).String())
}

func resolveDialectFromDriverType(typeName string) string {
	lower := strings.ToLower(typeName)
	switch {
	case strings.Contains(lower, "mysql"):
		return "mysql"
	case strings.Contains(lower, "pq") || strings.Contains(lower, "postgres") || strings.Contains(lower, "pgx"):
		return "postgres"
	case strings.Contains(lower, "sqlite"):
		return "sqlite"
	default:
		return "generic"
	}
}
