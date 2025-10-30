//go:build integration

package filepath_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/require"
)

func TestJoinPathInjectionBlockIsDeferred(t *testing.T) {
	zen.Protect()

	// Enable blocking so that Zen should cause os.OpenFile to return an error
	original := config.IsBlockingEnabled()
	config.SetBlocking(true)

	req := httptest.NewRequest("GET", "/route?path=../test.txt", nil)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, "/route?path=../test.txt", "test", &ip, nil)

	request.WrapWithGLS(ctx, func() {
		path := filepath.Join("/tmp/", "../test.txt")
		_, err := os.OpenFile(path, os.O_RDONLY, 0o600)

		var detectedErr *vulnerabilities.AttackDetectedError
		require.ErrorAs(t, err, &detectedErr)
	})

	config.SetBlocking(original)
}
