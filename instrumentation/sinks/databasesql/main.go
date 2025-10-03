package databasesql

import (
	"fmt"

	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/sqlinjection"
)

func Examine(query string, op string) error {
	fmt.Println("Examining query:", query)

	ctx := context.Get()
	if ctx == nil {
		return nil
	}

	return vulnerabilities.Scan(*ctx, op, sqlinjection.SQLInjectionVulnerability, []string{
		query /* dialect */, "default",
	})
}
