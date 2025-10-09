package databasesql

import (
	"context"
	"fmt"

	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/sqlinjection"
)

func Examine(ctx context.Context, query string, op string) error {
	fmt.Println("Examining query:", query)

	return vulnerabilities.Scan(ctx, op, sqlinjection.SQLInjectionVulnerability, []string{
		query /* dialect */, "default",
	})
}
