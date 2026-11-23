//go:build integration

package http_test

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/AikidoSec/firewall-go/instrumentation"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAIHTTPInstrumentation(t *testing.T) {
	require.NoError(t, zen.Protect())
	config.UpdateServiceConfig(&aikido_types.CloudConfigData{}, nil)

	const body = `{"model":"gpt-4o","usage":{"prompt_tokens":10,"completion_tokens":5}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("gzip") == "true" {
			w.Header().Set("Content-Encoding", "gzip")

			writer := gzip.NewWriter(w)
			_, _ = io.WriteString(writer, body)
			_ = writer.Close()
			return
		}

		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()

	for _, query := range []string{"?api_key=secret", "?gzip=true"} {
		t.Run(query, func(t *testing.T) {
			agent.Stats().GetAndClearAI()

			resp, err := http.Post(server.URL+"/proxy/v1/chat/completions"+query, "application/json", nil)
			require.NoError(t, err)
			assert.Empty(t, agent.Stats().GetAndClearAI(), "body is not read ahead")

			got, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())

			assert.Equal(t, body, string(got))
			stats := agent.Stats().GetAndClearAI()
			require.Len(t, stats, 1)
			assert.Equal(t, server.URL, stats[0].Provider)
			assert.Equal(t, "gpt-4o", stats[0].Model)
			assert.Equal(t, 1, stats[0].Calls)
			assert.Equal(t, 10, stats[0].Tokens.Input)
			assert.Equal(t, 5, stats[0].Tokens.Output)
			assert.Equal(t, 15, stats[0].Tokens.Total)
		})
	}
}
