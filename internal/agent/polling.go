package agent

import (
	"context"
	"errors"
	"log/slog"
	"math/rand"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/polling"
)

var (
	heartbeatRoutine     *polling.Routine
	configPollingRoutine *polling.Routine
	sseCancel            context.CancelFunc

	minHeartbeatIntervalInMS = 120000
)

const (
	sseInitialBackoff  = 5 * time.Second
	sseMaxBackoff      = 60 * time.Second
	sseStableThreshold = 30 * time.Second
)

func startPolling() {
	heartbeatRoutine = polling.Start(10*time.Minute, sendHeartbeatEvent)
	configPollingRoutine = polling.Start(1*time.Minute, refreshCloudConfig)

	var ctx context.Context
	ctx, sseCancel = context.WithCancel(context.Background()) //nolint:gosec // cancel is stored in sseCancel and called in stopPolling
	go runSSESubscription(ctx)
}

func stopPolling() {
	if heartbeatRoutine != nil {
		heartbeatRoutine.Stop()
	}
	if configPollingRoutine != nil {
		configPollingRoutine.Stop()
	}
	if sseCancel != nil {
		sseCancel()
	}
}

// runSSESubscription connects to the realtime SSE endpoint and calls
// refreshCloudConfigIfNewer on each config-updated event. Reconnects with
// exponential backoff and jitter on failure. The 1-minute poll remains as a fallback.
func runSSESubscription(ctx context.Context) {
	backoff := sseInitialBackoff
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		client := GetCloudClient()
		if client == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}

		connectedAt := time.Now()
		err := client.SubscribeToConfigUpdates(ctx, func(configUpdatedAt int64) {
			log.Info("Realtime config update received")
			refreshCloudConfigIfNewer(configUpdatedAt)
		})
		if ctx.Err() != nil {
			return
		}

		if errors.Is(err, cloud.ErrNotRetryable) {
			log.Warn("SSE config stream: non-retryable error, stopping", slog.Any("error", err))
			return
		}

		if err != nil {
			log.Warn("SSE config stream disconnected", slog.Any("error", err))
		}

		if time.Since(connectedAt) >= sseStableThreshold {
			backoff = sseInitialBackoff
		}

		jitter := time.Duration(rand.Int63n(int64(backoff/2) + 1)) //nolint:gosec // jitter does not need cryptographic randomness
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff + jitter):
		}

		if backoff < sseMaxBackoff {
			backoff *= 2
			if backoff > sseMaxBackoff {
				backoff = sseMaxBackoff
			}
		}
	}
}

// refreshCloudConfigIfNewer fetches and applies the full cloud config only if
// the provided configUpdatedAt is newer than the locally stored value.
func refreshCloudConfigIfNewer(configUpdatedAtMs int64) {
	if !time.UnixMilli(configUpdatedAtMs).After(config.GetCloudConfigUpdatedAt()) {
		return
	}

	client := GetCloudClient()
	if client == nil {
		return
	}

	cloudConfig, err := client.FetchConfig()
	if err != nil {
		log.Warn("Error fetching cloud config after realtime update", slog.Any("error", err))
		return
	}

	applyCloudConfig(client, cloudConfig)
}

// refreshCloudConfig checks if config has changed before fetching the full config
// to avoid unnecessary calls to the API
func refreshCloudConfig() {
	client := GetCloudClient()
	if client == nil {
		return
	}

	// Check if cloud config has been updated
	lastUpdatedAt := client.FetchConfigUpdatedAt()
	if !lastUpdatedAt.After(config.GetCloudConfigUpdatedAt()) {
		return
	}

	// Something has changed, so fetch the full cloud config
	cloudConfig, err := client.FetchConfig()
	if err != nil {
		log.Warn("Error fetching cloud config", slog.Any("error", err))
		return
	}

	applyCloudConfig(client, cloudConfig)
}

func sendHeartbeatEvent() {
	client := GetCloudClient()
	if client == nil {
		return
	}

	cloudConfig, err := client.SendHeartbeatEvent(getAgentInfo(),
		cloud.HeartbeatData{
			Hostnames:           stateCollector.GetAndClearHostnames(),
			Routes:              stateCollector.GetRoutesAndClear(),
			Users:               stateCollector.GetUsersAndClear(),
			Stats:               stateCollector.Stats().GetAndClear(),
			MiddlewareInstalled: stateCollector.IsMiddlewareInstalled(),
		})
	if err != nil {
		log.Warn("Error sending heartbeat event", slog.Any("error", err))
		return
	}

	applyCloudConfig(client, cloudConfig)
}

// calculateHeartbeatInterval returns a faster polling interval (1 minute) for new agents
// until they send their first stats, then switches to the cloud-configured interval
// (minimum 2 minutes) to reduce unnecessary load.
func calculateHeartbeatInterval(heartbeatIntervalInMS int, receivedAnyStats bool) time.Duration {
	if !receivedAnyStats {
		return 1 * time.Minute
	} else if heartbeatIntervalInMS >= minHeartbeatIntervalInMS {
		log.Debug("Calculating heartbeat interval", slog.Int("interval", heartbeatIntervalInMS))
		return time.Duration(heartbeatIntervalInMS) * time.Millisecond
	}
	return 0
}

func resetHeartbeatTicker(newInterval time.Duration) {
	if heartbeatRoutine != nil && newInterval > 0 {
		log.Debug("Resetting HeartbeatTicker", slog.String("interval", newInterval.String()))
		heartbeatRoutine.Reset(newInterval)
	}
}
