package attackwave

import (
	"maps"
	"slices"
	"strings"

	"github.com/AikidoSec/firewall-go/internal/request"
)

var dangerousKeywords = []string{
	"SELECT (CASE WHEN",
	"SELECT COUNT(",
	"SLEEP(",
	"WAITFOR DELAY",
	"SELECT LIKE(CHAR(",
	"INFORMATION_SCHEMA.COLUMNS",
	"INFORMATION_SCHEMA.TABLES",
	"MD5(",
	"DBMS_PIPE.RECEIVE_MESSAGE",
	"SYSIBM.SYSTABLES",
	"RANDOMBLOB(",
	"SELECT * FROM",
	"1'='1",
	"PG_SLEEP(",
	"UNION ALL SELECT",
	"../",
}

// queryContainsDangerousPayload checks if query parameters contain common attack patterns
func queryContainsDangerousPayload(ctx *request.Context) bool {
	if ctx == nil || ctx.Query == nil {
		return false
	}

	// Collect all value slices from the map
	valueSlices := slices.Collect(maps.Values(ctx.Query))

	// Flatten and check
	allValues := slices.Concat(valueSlices...)
	return slices.ContainsFunc(allValues, containsDangerousPattern)
}

func containsDangerousPattern(str string) bool {
	// Performance optimization: skip very short or very long strings
	if len(str) < 5 || len(str) > 1000 {
		return false
	}

	upperStr := strings.ToUpper(str)

	for _, keyword := range dangerousKeywords {
		if strings.Contains(upperStr, keyword) {
			return true
		}
	}

	return false
}
