//go:build integration

package os_test

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/require"
)

func TestOpenFileIsAutomaticallyInstrumented(t *testing.T) {
	require.NoError(t, zen.Protect())

	// Enable blocking so that Zen should cause os.OpenFile to return an error
	original := config.IsBlockingEnabled()
	config.SetBlocking(true)

	req := httptest.NewRequest("GET", "/route?path=../test.txt", nil)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, "/route?path=../test.txt", "test", &ip, nil)

	request.WrapWithGLS(ctx, func() {
		_, err := os.OpenFile("/tmp/"+"../test.txt", os.O_RDONLY, 0o600)

		var detectedErr *vulnerabilities.AttackDetectedError
		require.ErrorAs(t, err, &detectedErr)
	})

	config.SetBlocking(original)
}
