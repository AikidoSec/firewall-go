package utils

import (
	"time"
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
