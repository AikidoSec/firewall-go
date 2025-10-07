package utils

import (
	"slices"
	"time"

	"github.com/AikidoSec/firewall-go/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/agent/config"
	"github.com/AikidoSec/firewall-go/agent/globals"
)

func StartPollingRoutine(stopChan chan struct{}, ticker *time.Ticker, pollingFunction func()) {
	go func() {
		for {
			select {
			case <-ticker.C:
				pollingFunction()
			case <-stopChan:
				ticker.Stop()
				return
			}
		}
	}()
}

func StopPollingRoutine(stopChan chan struct{}) {
	close(stopChan)
}

func IsBlockingEnabled() bool {
	globals.CloudConfigMutex.Lock()
	defer globals.CloudConfigMutex.Unlock()

	if globals.CloudConfig.Block == nil {
		return config.GetBlocking()
	}
	return *globals.CloudConfig.Block
}

func GetTime() int64 {
	return time.Now().UnixMilli()
}

func GetUserByID(userID string) *aikido_types.User {
	if userID == "" {
		return nil
	}

	globals.UsersMutex.Lock()
	defer globals.UsersMutex.Unlock()

	user, exists := globals.Users[userID]
	if !exists {
		return nil
	}
	return &user
}

func ComputeAverage(times []int64) float64 {
	if len(times) == 0 {
		return 0
	}
	var total int64
	for _, t := range times {
		total += t
	}

	return float64(total) / float64(len(times)) / 1e6
}

func ComputePercentiles(times []int64) map[string]float64 {
	if len(times) == 0 {
		return map[string]float64{
			"P50": 0,
			"P90": 0,
			"P95": 0,
			"P99": 0,
		}
	}

	slices.Sort(times)

	percentiles := map[string]float64{}
	percentiles["P50"] = float64(times[len(times)/2]) / 1e6
	percentiles["P90"] = float64(times[int(0.9*float64(len(times)))]) / 1e6
	percentiles["P95"] = float64(times[int(0.95*float64(len(times)))]) / 1e6
	percentiles["P99"] = float64(times[int(0.99*float64(len(times)))]) / 1e6

	return percentiles
}
