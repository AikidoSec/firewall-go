package slidingwindow

import "sync"

// Window tracks events within a sliding window time
type Window struct {
	timestamps []int64
	windowSize int64 // in same units as timestamp
	maxCount   int

	mu sync.Mutex
}

func New(windowSize int64, maxCount int) *Window {
	return &Window{
		timestamps: make([]int64, 0),
		windowSize: windowSize,
		maxCount:   maxCount,
	}
}

// TryRecord attemps to record a timestamp
// Returns true if recorded successfully, false if limit would be exceeded.
func (w *Window) TryRecord(timestamp int64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.cleanOld(timestamp)

	if len(w.timestamps) >= w.maxCount {
		return false
	}

	w.timestamps = append(w.timestamps, timestamp)
	return true
}

// Count returns the number of events in the current window
func (w *Window) Count(currentTimestamp int64) int {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.cleanOld(currentTimestamp)
	return len(w.timestamps)
}

// RetryAfter returns how long until the oldest event in the window expires, freeing a slot.
func (w *Window) RetryAfter(timestamp int64) int64 {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.cleanOld(timestamp)

	if len(w.timestamps) == 0 {
		return 0
	}

	retryAfter := w.timestamps[0] + w.windowSize - timestamp
	if retryAfter < 0 {
		return 0
	}

	return retryAfter
}

// cleanOld removes timestamps outside the window (must be called with a lock)
func (w *Window) cleanOld(currentTime int64) {
	windowStart := currentTime - w.windowSize

	// Find the first timestamp within the window
	cutoffIndex := 0
	for cutoffIndex < len(w.timestamps) && w.timestamps[cutoffIndex] <= windowStart {
		cutoffIndex++
	}

	// Keep only timestamps from cutoffIndex onwards
	w.timestamps = w.timestamps[cutoffIndex:]
}
