package agent

import (
	"context"
	"errors"
	"log/slog"
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/polling"
)

var (
	heartbeatRoutine     *polling.Routine
	configPollingRoutine *polling.Routine

	minHeartbeatIntervalInMS = 120000

	heartbeatCounter        atomic.Int64
	steadyHeartbeatInterval atomic.Int64 // time.Duration(nanoseconds)

	lastConfigRefreshAttemptAt atomic.Int64 // unix nanoseconds
)

const (
	defaultHeartbeatInterval = 10 * time.Minute
	firstHeartbeatDelay      = 30 * time.Second
	secondHeartbeatDelay     = 2 * time.Minute

	sseInitialBackoff  = 5 * time.Second
	sseMaxBackoff      = 60 * time.Second
	sseStableThreshold = 30 * time.Second

	configRefreshThrottle = 9 * time.Second
)

func startPolling() {
	heartbeatCounter.Store(0)
	steadyHeartbeatInterval.Store(int64(defaultHeartbeatInterval))

	heartbeatRoutine = polling.Start(agentCtx, heartbeatInterval(), func() { sendHeartbeatEvent(agentCtx) })
	configPollingRoutine = polling.Start(agentCtx, 1*time.Minute, refreshCloudConfig)
}

func stopPolling() {
	if heartbeatRoutine != nil {
		heartbeatRoutine.Stop()
	}
	if configPollingRoutine != nil {
		configPollingRoutine.Stop()
	}
}

// runSSESubscription reconnects with exponential backoff and jitter until ctx is cancelled.
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
			log.Debug("SSE config stream disconnected, reconnecting", slog.Any("error", err))
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

// configUpdateArrivedTooFast reports whether a refresh happened within configRefreshThrottle.
func configUpdateArrivedTooFast() bool {
	now := time.Now()
	if now.Sub(time.Unix(0, lastConfigRefreshAttemptAt.Load())) < configRefreshThrottle {
		return true
	}

	lastConfigRefreshAttemptAt.Store(now.UnixNano())
	return false
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

	if configUpdateArrivedTooFast() {
		log.Debug("SSE config-updated event ignored by refresh throttle")
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

func sendHeartbeatEvent(ctx context.Context) {
	defer advanceHeartbeatSchedule()

	client := GetCloudClient()
	if client == nil {
		return
	}

	cloudConfig, err := client.SendHeartbeatEvent(ctx, getAgentInfo(),
		cloud.HeartbeatData{
			Hostnames:           stateCollector.GetAndClearHostnames(),
			Routes:              stateCollector.GetRoutesAndClear(),
			Users:               stateCollector.GetUsersAndClear(),
			Stats:               stateCollector.Stats().GetAndClear(),
			AI:                  stateCollector.Stats().GetAndClearAI(),
			MiddlewareInstalled: stateCollector.IsMiddlewareInstalled(),
		})
	if err != nil {
		log.Warn("Error sending heartbeat event", slog.Any("error", err))
		return
	}

	applyCloudConfig(client, cloudConfig)
}

// advanceHeartbeatSchedule is deferred in sendHeartbeatEvent, so it runs even after a failed send.
func advanceHeartbeatSchedule() {
	counter := heartbeatCounter.Add(1)
	resetHeartbeatTicker(heartbeatIntervalForCounter(counter))
}

func heartbeatInterval() time.Duration {
	return heartbeatIntervalForCounter(heartbeatCounter.Load())
}

// heartbeatIntervalForCounter ramps 30s, then 2m, then the steady-state interval.
func heartbeatIntervalForCounter(counter int64) time.Duration {
	switch counter {
	case 0:
		return firstHeartbeatDelay
	case 1:
		return secondHeartbeatDelay
	default:
		return time.Duration(steadyHeartbeatInterval.Load())
	}
}

func updateSteadyHeartbeatInterval(heartbeatIntervalInMS int) {
	if heartbeatIntervalInMS < minHeartbeatIntervalInMS {
		return
	}

	log.Debug("Updating steady-state heartbeat interval", slog.Int("interval", heartbeatIntervalInMS))
	steadyHeartbeatInterval.Store(int64(time.Duration(heartbeatIntervalInMS) * time.Millisecond))
}

func resetHeartbeatTicker(newInterval time.Duration) {
	if heartbeatRoutine != nil && newInterval > 0 {
		log.Debug("Resetting HeartbeatTicker", slog.String("interval", newInterval.String()))
		heartbeatRoutine.Reset(newInterval)
	}
}
