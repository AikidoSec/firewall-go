package sql

import (
	"context"
	"errors"

	"github.com/AikidoSec/firewall-go/instrumentation/hooks"
	"github.com/AikidoSec/firewall-go/instrumentation/operation"
	"github.com/AikidoSec/firewall-go/vulnerabilities"
	"github.com/AikidoSec/firewall-go/vulnerabilities/sqlinjection"
	"github.com/AikidoSec/firewall-go/zen"
)

// ExamineContext checks for SQL injection vulnerabilities in database queries.
// This function is called by the instrumentation framework to scan SQL queries
// before they are executed against the database.
func ExamineContext(ctx context.Context, query string, op string, dialect string) error {
	if !zen.ShouldProtect() {
		return nil
	}

	hooks.OnOperationCall(op, operation.KindSQL)

	err := vulnerabilities.ScanWithOptions(ctx, op, sqlinjection.SQLInjectionVulnerability, &sqlinjection.ScanArgs{
		Statement: query,
		Dialect:   dialect,
	}, vulnerabilities.ScanOptions{Module: "database/sql"})
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
