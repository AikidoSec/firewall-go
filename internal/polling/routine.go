package polling

import (
	"context"
	"sync"
	"time"
)

const minInterval = time.Millisecond

type Routine struct {
	ticker *time.Ticker
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex
}

func Start(interval time.Duration, fn func()) *Routine {
	if interval <= 0 {
		interval = minInterval
	}

	ctx, cancel := context.WithCancel(context.Background())

	r := &Routine{
		ticker: time.NewTicker(interval),
		cancel: cancel,
	}

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer r.ticker.Stop()
		for {
			select {
			case <-r.ticker.C:
				fn()
			case <-ctx.Done():
				return
			}
		}
	}()

	return r
}

// Stop stops the polling routine and waits for the goroutine to complete.
// Safe to call multiple times and from multiple goroutines.
func (r *Routine) Stop() {
	r.cancel()
	r.wg.Wait()
}

// Reset resets the interval of the polling routine
func (r *Routine) Reset(interval time.Duration) {
	if interval <= 0 {
		interval = minInterval
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.ticker.Reset(interval)
}
