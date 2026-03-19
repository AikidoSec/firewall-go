package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var dialectPayloads = map[string]string{
	"postgres": "Fluffy' || current_user || '",
	"mysql":    "Fluffy' OR '1'='1",
	"generic":  "Fluffy' OR '1'='1",
}

func TestSQLInjection(t *testing.T) {
	dialect := appSQLDialect()
	if dialect == "" {
		t.Skip("APP_SQL_DIALECT not set, skipping SQL injection tests")
	}

	maliciousInput, ok := dialectPayloads[dialect]
	if !ok {
		maliciousInput = "Fluffy' OR '1'='1"
	}

	client := &http.Client{Timeout: 5 * time.Second}

	t.Run("blocks SQL injection attack", func(t *testing.T) {
		body := map[string]string{"name": maliciousInput}
		jsonBody, err := json.Marshal(body)
		require.NoError(t, err)

		resp, err := client.Post(appURL()+"/api/create", "application/json", bytes.NewBuffer(jsonBody))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		event := waitForEvent(t, 5*time.Second, func(ev map[string]any) bool {
			return ev["type"] == "detected_attack"
		})

		attack, ok := event["attack"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "sql_injection", attack["kind"])
		assert.Equal(t, true, attack["blocked"])
		assert.Contains(t, attack["payload"], maliciousInput)

		metadata, ok := attack["metadata"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, dialect, metadata["dialect"])

		request, ok := event["request"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "POST", request["method"])
		assert.Contains(t, request["url"], "/api/create")

		agent, ok := event["agent"].(map[string]any)
		require.True(t, ok)
		assert.NotEmpty(t, agent["hostname"])
		assert.NotEmpty(t, agent["version"])
	})

	t.Run("allows normal requests", func(t *testing.T) {
		resp, err := client.Get(appURL() + "/api/pets")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		safeInput := "Good Pet"
		body := map[string]string{"name": safeInput}
		jsonBody, err := json.Marshal(body)
		require.NoError(t, err)

		resp, err = client.Post(appURL()+"/api/create", "application/json", bytes.NewBuffer(jsonBody))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
