package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This test suite runs with AIKIDO_DISABLE=true
// Requests should NOT be blocked when the firewall is disabled

func TestDisabled(t *testing.T) {
	appURL := os.Getenv("APP_URL")
	if appURL == "" {
		appURL = "http://localhost:8080"
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	t.Run("does not block SQL injection when disabled", func(t *testing.T) {
		// SQL injection attack in POST body
		maliciousInput := "Fluffy' || current_user || '"
		body := map[string]string{"name": maliciousInput}
		jsonBody, err := json.Marshal(body)
		require.NoError(t, err)

		resp, err := client.Post(appURL+"/api/create", "application/json", bytes.NewBuffer(jsonBody))
		require.NoError(t, err)
		defer resp.Body.Close()

		// When disabled, should NOT block (no 500 error)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
