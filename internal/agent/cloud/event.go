package cloud

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/AikidoSec/firewall-go/internal/log"
)

var ErrNoTokenSet = errors.New("no token set")

func (c *Client) sendCloudRequest(endpoint string, route string, method string, payload any) ([]byte, error) {
	if c.token == "" {
		return nil, ErrNoTokenSet
	}

	apiEndpoint, err := url.JoinPath(endpoint, route)
	if err != nil {
		return nil, fmt.Errorf("failed to build API endpoint: %v", err)
	}

	var req *http.Request
	var body io.Reader

	if payload != nil {
		jsonData, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal payload: %v", err)
		}
		body = bytes.NewBuffer(jsonData)
	}

	log.Debug("Sending request", slog.String("method", method), slog.String("endpoint", apiEndpoint))
	req, err = http.NewRequest(method, apiEndpoint, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Warn("failed to close response body", slog.Any("error", err))
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-OK response: %s", resp.Status)
	}

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	return responseBody, nil
}
