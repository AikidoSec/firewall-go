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
	"time"

	"github.com/AikidoSec/firewall-go/internal/log"
)

const configStreamRoute = "/api/runtime/stream"

var sseReadTimeout = 70 * time.Second

// ErrNotRetryable is returned when the server responds with a status code that
// indicates retrying will not help (e.g. 401, 403).
var ErrNotRetryable = errors.New("not retryable")

type configUpdatedData struct {
	ConfigUpdatedAt int64 `json:"configUpdatedAt"`
}

// SubscribeToConfigUpdates opens an SSE connection to the realtime endpoint and
// calls onUpdate with the configUpdatedAt timestamp whenever a config-updated
// event is received. Blocks until the connection is closed or ctx is cancelled.
// The caller is responsible for reconnecting on error.
func (c *Client) SubscribeToConfigUpdates(ctx context.Context, onUpdate func(configUpdatedAt int64)) error {
	readCtx, cancelRead := context.WithCancel(ctx)
	defer cancelRead()

	req, err := http.NewRequestWithContext(readCtx, http.MethodGet,
		c.realtimeEndpoint+configStreamRoute, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.token)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

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

	readTimeout := sseReadTimeout
	resetCh := make(chan struct{}, 1)
	go func() {
		idleTimer := time.NewTimer(readTimeout)
		defer idleTimer.Stop()
		for {
			select {
			case <-resetCh:
				if !idleTimer.Stop() {
					select {
					case <-idleTimer.C:
					default:
					}
				}
				idleTimer.Reset(readTimeout)
			case <-idleTimer.C:
				cancelRead()
				return
			case <-readCtx.Done():
				return
			}
		}
	}()

	scanner := bufio.NewScanner(resp.Body)
	parser := &sseParser{}

	for scanner.Scan() {
		select {
		case resetCh <- struct{}{}:
		default:
		}

		event, ok := parser.feedLine(scanner.Text())
		if !ok || event.name != "config-updated" {
			continue
		}

		var data configUpdatedData
		if err := json.Unmarshal([]byte(event.data), &data); err != nil {
			log.Debug("SSE: failed to parse config-updated payload", slog.Any("error", err))
			continue
		}
		onUpdate(data.ConfigUpdatedAt)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

type sseEvent struct {
	name string
	data string
}

type sseParser struct {
	eventName string
	dataLines []string
}

func (p *sseParser) feedLine(line string) (sseEvent, bool) {
	switch {
	case strings.HasPrefix(line, "event:"):
		p.eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
	case strings.HasPrefix(line, "data:"):
		p.dataLines = append(p.dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
	case line == "":
		event := sseEvent{name: p.eventName, data: strings.Join(p.dataLines, "\n")}
		p.eventName = ""
		p.dataLines = nil
		return event, true
	}
	return sseEvent{}, false
}
