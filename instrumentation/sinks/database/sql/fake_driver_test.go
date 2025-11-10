package sql_test

import (
	"database/sql"
	"database/sql/driver"
)

func init() {
	sql.Register("test", &testDriver{})
}

type testDriver struct{}

func (d *testDriver) Open(name string) (driver.Conn, error) {
	return &testConn{}, nil
}

type testConn struct{}

func (c *testConn) Prepare(query string) (driver.Stmt, error) {
	return &testStmt{}, nil
}

func (c *testConn) Close() error { return nil }

func (c *testConn) Begin() (driver.Tx, error) {
	return nil, driver.ErrSkip // Not implementing transactions
}

type testStmt struct{}

func (s *testStmt) Close() error                                    { return nil }
func (s *testStmt) NumInput() int                                   { return -1 }
func (s *testStmt) Exec(args []driver.Value) (driver.Result, error) { return nil, nil }
func (s *testStmt) Query(args []driver.Value) (driver.Rows, error)  { return nil, nil }
