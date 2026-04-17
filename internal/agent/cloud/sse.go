package cloud

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
)

const configStreamRoute = "/api/runtime/stream"

// SubscribeToConfigUpdates opens an SSE connection to the realtime endpoint and
// calls onUpdate whenever a config-updated event is received. Blocks until the
// connection is closed or ctx is cancelled. The caller is responsible for
// reconnecting on error.
func (c *Client) SubscribeToConfigUpdates(ctx context.Context, onUpdate func()) error {
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var eventName string

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case line == "":
			if eventName == "config-updated" {
				onUpdate()
			}
			eventName = ""
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}
