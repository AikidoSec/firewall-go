//go:build !integration

package sql

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveDialectFromDriverType_PgxStdlib(t *testing.T) {
	// pgx/v5/stdlib type name is "*stdlib.Driver", which has no "pgx" in it, but the
	// package path "github.com/jackc/pgx/v5/stdlib" does.
	assert.Equal(t, "postgres", resolveDialectFromDriverType("*stdlib.Driver github.com/jackc/pgx/v5/stdlib"))
}
