package transform

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// parseFunc parses src and returns the first FuncDecl found.
func parseFunc(t *testing.T, src string) *ast.FuncDecl {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, 0)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			return fn
		}
	}
	t.Fatal("no FuncDecl found in source")
	return nil
}

// TestDot_Function verifies dot.Function() returns a non-nil *function.
func TestDot_Function(t *testing.T) {
	fn := parseFunc(t, `package p; func Foo() {}`)
	d := &dot{fn: fn}
	if d.Function() == nil {
		t.Fatal("expected non-nil function")
	}
}

// TestFunction_Name tests the Name method.
func TestFunction_Name(t *testing.T) {
	fn := parseFunc(t, `package p; func MyFunc() {}`)
	f := &function{fn: fn}
	if got := f.Name(); got != "MyFunc" {
		t.Errorf("Name() = %q, want %q", got, "MyFunc")
	}
}

// TestFunction_Argument tests retrieving named parameters by index.
func TestFunction_Argument(t *testing.T) {
	fn := parseFunc(t, `package p; func Foo(ctx int, query string, extra bool) {}`)
	f := &function{fn: fn}

	tests := []struct {
		idx  int
		want string
	}{
		{0, "ctx"},
		{1, "query"},
		{2, "extra"},
		{3, ""},  // out of bounds
		{-1, ""}, // negative index
	}
	for _, tt := range tests {
		if got := f.Argument(tt.idx); got != tt.want {
			t.Errorf("Argument(%d) = %q, want %q", tt.idx, got, tt.want)
		}
	}
}

// TestFunction_Argument_NoParams tests a function with no parameters.
func TestFunction_Argument_NoParams(t *testing.T) {
	fn := parseFunc(t, `package p; func Foo() {}`)
	f := &function{fn: fn}
	if got := f.Argument(0); got != "" {
		t.Errorf("Argument(0) = %q, want empty string", got)
	}
}

// TestFunction_Argument_UnnamedParam tests an unnamed parameter.
func TestFunction_Argument_UnnamedParam(t *testing.T) {
	fn := parseFunc(t, `package p; func Foo(_ string) {}`)
	f := &function{fn: fn}
	// The blank identifier is still a name in the AST.
	if got := f.Argument(0); got != "_" {
		t.Errorf("Argument(0) = %q, want %q", got, "_")
	}
}

// TestFunction_Receiver tests the Receiver method for a method with a named receiver.
func TestFunction_Receiver(t *testing.T) {
	fn := parseFunc(t, `package p; type T struct{}; func (db *T) Foo() {}`)
	f := &function{fn: fn}
	if got := f.Receiver(); got != "db" {
		t.Errorf("Receiver() = %q, want %q", got, "db")
	}
}

// TestFunction_Receiver_NoReceiver tests Receiver on a plain function.
func TestFunction_Receiver_NoReceiver(t *testing.T) {
	fn := parseFunc(t, `package p; func Foo() {}`)
	f := &function{fn: fn}
	if got := f.Receiver(); got != "" {
		t.Errorf("Receiver() = %q, want empty string", got)
	}
}

// TestFunction_Receiver_UnnamedReceiver tests a method with an unnamed receiver.
func TestFunction_Receiver_UnnamedReceiver(t *testing.T) {
	fn := parseFunc(t, `package p; type T struct{}; func (*T) Foo() {}`)
	f := &function{fn: fn}
	if got := f.Receiver(); got != "" {
		t.Errorf("Receiver() = %q, want empty string for unnamed receiver", got)
	}
}
