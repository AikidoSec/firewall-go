package sql_test

import (
	"database/sql"
	"database/sql/driver"
	"io"
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
	return &testStmt{query: query}, nil
}

func (c *testConn) Close() error {
	return nil
}

func (c *testConn) Begin() (driver.Tx, error) {
	return &testTx{}, nil
}

type testTx struct{}

func (t *testTx) Commit() error {
	return nil
}

func (t *testTx) Rollback() error {
	return nil
}

type testStmt struct {
	query string
}

func (s *testStmt) Close() error {
	return nil
}

func (s *testStmt) NumInput() int {
	return -1 // Variable number of inputs
}

func (s *testStmt) Exec(args []driver.Value) (driver.Result, error) {
	return &testResult{}, nil
}

func (s *testStmt) Query(args []driver.Value) (driver.Rows, error) {
	return &testRows{}, nil
}

type testResult struct{}

func (r *testResult) LastInsertId() (int64, error) {
	return 1, nil
}

func (r *testResult) RowsAffected() (int64, error) {
	return 1, nil
}

// testRows implements driver.Rows
type testRows struct {
	closed    bool
	nextCount int
}

func (r *testRows) Columns() []string {
	return []string{"id", "name", "email"}
}

func (r *testRows) Close() error {
	r.closed = true
	return nil
}

// Next is called to populate the next row of data into the provided slice.
// Returns io.EOF when there are no more rows.
func (r *testRows) Next(dest []driver.Value) error {
	if r.closed {
		return io.EOF
	}

	// Return one row, then EOF
	if r.nextCount > 0 {
		return io.EOF
	}

	r.nextCount++

	// Populate with dummy data
	dest[0] = int64(1)
	dest[1] = "test_user"
	dest[2] = "test@example.com"

	return nil
}
