//go:build !integration

package sql_test

import (
	"database/sql/driver"
	"testing"

	sinksql "github.com/AikidoSec/firewall-go/instrumentation/sinks/database/sql"
	"github.com/stretchr/testify/assert"
)

type fakeMysqlDriver2 struct{}

func (d *fakeMysqlDriver2) Open(name string) (driver.Conn, error) { return nil, nil }

type fakePostgresDriver struct{}

func (d *fakePostgresDriver) Open(name string) (driver.Conn, error) { return nil, nil }

type fakeSQLiteDriver struct{}

func (d *fakeSQLiteDriver) Open(name string) (driver.Conn, error) { return nil, nil }

type fakeUnknownDriver struct{}

func (d *fakeUnknownDriver) Open(name string) (driver.Conn, error) { return nil, nil }

func TestGetDialectFromDriver(t *testing.T) {
	tests := []struct {
		name            string
		driver          driver.Driver
		expectedDialect string
	}{
		{"mysql", &fakeMysqlDriver2{}, "mysql"},
		{"postgres", &fakePostgresDriver{}, "postgres"},
		{"sqlite", &fakeSQLiteDriver{}, "sqlite"},
		{"unknown", &fakeUnknownDriver{}, "generic"},
		{"nil", nil, "generic"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedDialect, sinksql.GetDialectFromDriver(tt.driver))
		})
	}
}
