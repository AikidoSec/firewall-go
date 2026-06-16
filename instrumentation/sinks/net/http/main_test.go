package http

import (
	"os"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/testutil"
)

func TestMain(m *testing.M) {
	testutil.RegisterGLSFallback()
	os.Exit(m.Run())
}
