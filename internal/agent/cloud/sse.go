package cloud

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/AikidoSec/firewall-go/internal/log"
)

const configStreamRoute = "/api/runtime/stream"

// ErrNotRetryable is returned when the server responds with a status code that
// indicates retrying will not help (e.g. 401, 403).
var ErrNotRetryable = errors.New("not retryable")

type configUpdatedData struct {
	ServiceID       int   `json:"serviceId"`
	ConfigUpdatedAt int64 `json:"configUpdatedAt"`
}

// SubscribeToConfigUpdates opens an SSE connection to the realtime endpoint and
// calls onUpdate with the configUpdatedAt timestamp whenever a config-updated
// event is received. Blocks until the connection is closed or ctx is cancelled.
// The caller is responsible for reconnecting on error.
func (c *Client) SubscribeToConfigUpdates(ctx context.Context, onUpdate func(configUpdatedAt int64)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.realtimeEndpoint+configStreamRoute, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.token)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	// SSE connections must not time out, use a client without a timeout.
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn("failed to close response body", slog.Any("error", closeErr))
		}
	}()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("status %d: %w", resp.StatusCode, ErrNotRetryable)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var eventName, dataLine string

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			dataLine = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		case line == "":
			if eventName == "config-updated" {
				var data configUpdatedData
				if err := json.Unmarshal([]byte(dataLine), &data); err == nil {
					onUpdate(data.ConfigUpdatedAt)
				}
			}
			eventName = ""
			dataLine = ""
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}
