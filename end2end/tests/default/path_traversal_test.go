package tests

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathTraversal(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}

	t.Run("blocks path traversal attack", func(t *testing.T) {
		maliciousPath := "../../../etc/passwd"

		resp, err := client.Get(appURL() + "/api/read?path=" + maliciousPath)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		event := waitForEvent(t, 5*time.Second, func(ev map[string]any) bool {
			if ev["type"] != "detected_attack" {
				return false
			}
			attack, ok := ev["attack"].(map[string]any)
			return ok && attack["kind"] == "path_traversal"
		})

		attack, ok := event["attack"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "path_traversal", attack["kind"])
		assert.Equal(t, true, attack["blocked"])
		assert.Contains(t, attack["payload"], maliciousPath)

		request, ok := event["request"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "GET", request["method"])
		assert.Contains(t, request["url"], "/api/read")

		agent, ok := event["agent"].(map[string]any)
		require.True(t, ok)
		assert.NotEmpty(t, agent["hostname"])
		assert.NotEmpty(t, agent["version"])
	})

	t.Run("allows normal requests", func(t *testing.T) {
		resp, err := client.Get(appURL() + "/api/read?path=hello.txt")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode)
	})
}
