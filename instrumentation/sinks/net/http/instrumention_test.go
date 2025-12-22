//go:build integration

package http

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPClientInstrumentation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	agent.State().GetAndClearHostnames()

	resp, err := http.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "ok", string(body))

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	port, err := strconv.ParseUint(serverURL.Port(), 10, 32)
	require.NoError(t, err)

	hostnames := agent.State().GetAndClearHostnames()
	assert.Equal(t, []aikido_types.Hostname{
		{URL: serverURL.Hostname(), Port: uint32(port), Hits: 1},
	}, hostnames)
}
