package tests

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShellInjection(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}

	t.Run("blocks shell injection attack", func(t *testing.T) {
		maliciousInput := "echo hello; ls"

		resp, err := client.PostForm(appURL()+"/api/execute", url.Values{
			"user_command": {maliciousInput},
		})
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		event := waitForEvent(t, 5*time.Second, func(ev map[string]any) bool {
			if ev["type"] != "detected_attack" {
				return false
			}
			attack, ok := ev["attack"].(map[string]any)
			return ok && attack["kind"] == "shell_injection"
		})

		attack, ok := event["attack"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "shell_injection", attack["kind"])
		assert.Equal(t, true, attack["blocked"])
		assert.Contains(t, attack["payload"], maliciousInput)
		assert.Equal(t, "os/exec", attack["module"])

		request, ok := event["request"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "POST", request["method"])
		assert.Contains(t, request["url"], "/api/execute")

		agent, ok := event["agent"].(map[string]any)
		require.True(t, ok)
		assert.NotEmpty(t, agent["hostname"])
		assert.NotEmpty(t, agent["version"])
	})

	t.Run("allows normal requests", func(t *testing.T) {
		resp, err := client.PostForm(appURL()+"/api/execute", url.Values{
			"user_command": {"date"},
		})
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
