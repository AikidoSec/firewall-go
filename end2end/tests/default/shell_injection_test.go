package tests

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShellInjection(t *testing.T) {
	appURL := os.Getenv("APP_URL")
	if appURL == "" {
		appURL = "http://localhost:8080"
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	t.Run("blocks shell injection via POST body", func(t *testing.T) {
		resp, err := client.PostForm(appURL+"/api/execute", url.Values{
			"user_command": {"ls;cat /etc/passwd"},
		})
		require.NoError(t, err)
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "aikido firewall has blocked a shell injection")
	})

	t.Run("blocks shell injection via URL path", func(t *testing.T) {
		// Use pipe character for shell injection - no special URL encoding needed
		resp, err := client.Get(appURL + "/api/execute/ls|id")
		require.NoError(t, err)
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "aikido firewall has blocked a shell injection")
	})
}
