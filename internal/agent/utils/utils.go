package utils

import (
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
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
