package databasesql

import (
	"context"

	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/sqlinjection"
)

// Examine checks for SQL injection without a context (uses context.Background())
func Examine(query string, op string) error {
	return ExamineContext(context.Background(), query, op)
}

// ExamineContext checks for SQL injection with the provided context
func ExamineContext(ctx context.Context, query string, op string) error {
	return vulnerabilities.Scan(ctx, op, sqlinjection.SQLInjectionVulnerability, []string{
		query /* dialect */, "default",
	})
}
