package sql

import (
	"context"
	"errors"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
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
	if !zen.ShouldProtect() {
		return nil
	}

	agent.OnOperationCall(op, aikido_types.OperationKindSQL)

	err := vulnerabilities.Scan(ctx, op, sqlinjection.SQLInjectionVulnerability, &sqlinjection.ScanArgs{
		Statement: query,
		Dialect:   "default",
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
