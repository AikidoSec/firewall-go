package sql

import (
	"context"
	"errors"

	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/sqlinjection"
	"github.com/AikidoSec/firewall-go/zen"
)

// Examine checks for SQL injection on non-context database methods.
// Use this for methods like Query, QueryRow, Exec, and Prepare.
func Examine(query string, op string) error {
	return ExamineContext(context.Background(), query, op)
}

// ExamineContext checks for SQL injection vulnerabilities in database queries.
// This function is called by the instrumentation framework to scan SQL queries
// before they are executed against the database.
func ExamineContext(ctx context.Context, query string, op string) error {
	err := vulnerabilities.Scan(ctx, op, sqlinjection.SQLInjectionVulnerability, &sqlinjection.ScanArgs{
		Statement: query,
		Dialect:   "default",
	})
	if err != nil {
		return errors.Join(zen.ErrAttackBlocked, err)
	}

	return nil
}
