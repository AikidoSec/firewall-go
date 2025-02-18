package database_sql

import (
	"fmt"
	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/sql_injection"
)

func Examine(query string) error {
	fmt.Println("Examining query:", query)

	ctx := context.Get()
	if ctx == nil {
		return nil
	}

	return vulnerabilities.Scan(*ctx, sql_injection.SQLInjectionVulnerability, []string{
		query /* dialect */, "default",
	})
}
