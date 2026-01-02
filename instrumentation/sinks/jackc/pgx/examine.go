package pgx

import (
	"context"
	"errors"

	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/sqlinjection"
	"github.com/AikidoSec/firewall-go/zen"
)

// ExamineContext checks for SQL injection vulnerabilities in database queries.
// This function is called by the instrumentation framework to scan SQL queries
// before they are executed against the database.
func ExamineContext(ctx context.Context, query string, op string) error {
	if zen.IsDisabled() {
		return nil
	}

	err := vulnerabilities.Scan(ctx, op, sqlinjection.SQLInjectionVulnerability, &sqlinjection.ScanArgs{
		Statement: query,
		Dialect:   "postgres",
	})
	if err != nil {
		// Extract attack kind from error if available, otherwise default to SQL injection
		attackKind := vulnerabilities.KindSQLInjection
		var attackErr *vulnerabilities.AttackDetectedError
		if errors.As(err, &attackErr) {
			attackKind = attackErr.Kind
		}
		return errors.Join(zen.ErrAttackBlocked(attackKind), err)
	}

	return nil
}
