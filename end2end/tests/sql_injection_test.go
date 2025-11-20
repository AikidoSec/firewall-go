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

func TestSQLInjection(t *testing.T) {
	// Get app URL from environment (set by CI or test runner)
	appURL := os.Getenv("APP_URL")
	if appURL == "" {
		appURL = "http://localhost:8080" // Default for local testing
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	t.Run("blocks SQL injection attack", func(t *testing.T) {
		// SQL injection attack in POST body
		maliciousInput := "test' OR 1=1--"
		body := map[string]string{"name": maliciousInput}
		jsonBody, err := json.Marshal(body)
		require.NoError(t, err)

		resp, err := client.Post(appURL+"/api/create", "application/json", bytes.NewBuffer(jsonBody))
		require.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("allows normal requests", func(t *testing.T) {
		// Normal, safe request
		resp, err := client.Get(appURL + "/api/pets")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// SQL injection attack in POST body
		safeInput := "Good Pet"
		body := map[string]string{"name": safeInput}
		jsonBody, err := json.Marshal(body)
		require.NoError(t, err)

		resp, err = client.Post(appURL+"/api/create", "application/json", bytes.NewBuffer(jsonBody))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
