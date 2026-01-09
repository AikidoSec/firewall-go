package utils

import (
	"sync"
	"time"
)

type PollingRoutine struct {
	ticker   *time.Ticker
	stopChan chan struct{}
	wg       sync.WaitGroup
	mu       sync.Mutex
}

// StartPollingRoutine starts a new polling routine with the given interval and function
func StartPollingRoutine(interval time.Duration, fn func()) *PollingRoutine {
	pr := &PollingRoutine{
		ticker:   time.NewTicker(interval),
		stopChan: make(chan struct{}),
	}

	pr.wg.Add(1)
	go func() {
		defer pr.wg.Done()
		defer pr.ticker.Stop()
		for {
			select {
			case <-pr.ticker.C:
				fn()
			case <-pr.stopChan:
				return
			}
		}
	}()

	return pr
}

// Stop stops the polling routine and waits for the goroutine to complete
func (pr *PollingRoutine) Stop() {
	close(pr.stopChan)
	pr.wg.Wait()
}

// Reset resets the interval of the polling routine
func (pr *PollingRoutine) Reset(interval time.Duration) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	pr.ticker.Reset(interval)
}

func GetTime() int64 {
	return time.Now().UnixMilli()
}
