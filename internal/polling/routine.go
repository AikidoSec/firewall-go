package polling

import (
	"sync"
	"time"
)

type Routine struct {
	ticker   *time.Ticker
	stopChan chan struct{}
	wg       sync.WaitGroup
	mu       sync.Mutex
}

func Start(interval time.Duration, fn func()) *Routine {
	r := &Routine{
		ticker:   time.NewTicker(interval),
		stopChan: make(chan struct{}),
	}

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer r.ticker.Stop()
		for {
			select {
			case <-r.ticker.C:
				fn()
			case <-r.stopChan:
				return
			}
		}
	}()

	return r
}

// Stop stops the polling routine and waits for the goroutine to complete
func (r *Routine) Stop() {
	close(r.stopChan)
	r.wg.Wait()
}

// Reset resets the interval of the polling routine
func (r *Routine) Reset(interval time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ticker.Reset(interval)
}
