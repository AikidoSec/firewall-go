package utils

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestStartPollingRoutine(t *testing.T) {
	var callCount int64
	stopChan := make(chan struct{})
	ticker := time.NewTicker(10 * time.Millisecond)

	StartPollingRoutine(stopChan, ticker, func() {
		atomic.AddInt64(&callCount, 1)
	})

	time.Sleep(35 * time.Millisecond)
	StopPollingRoutine(stopChan)
	time.Sleep(10 * time.Millisecond)

	assert.Greater(t, atomic.LoadInt64(&callCount), int64(1))
}

func TestStopPollingRoutine(t *testing.T) {
	var callCount int64
	stopChan := make(chan struct{})
	ticker := time.NewTicker(10 * time.Millisecond)

	StartPollingRoutine(stopChan, ticker, func() {
		atomic.AddInt64(&callCount, 1)
	})

	time.Sleep(25 * time.Millisecond)
	StopPollingRoutine(stopChan)
	finalCount := atomic.LoadInt64(&callCount)
	time.Sleep(30 * time.Millisecond)

	assert.Equal(t, finalCount, atomic.LoadInt64(&callCount))
}

func TestGetTime(t *testing.T) {
	before := time.Now().UnixMilli()
	result := GetTime()
	after := time.Now().UnixMilli()

	assert.GreaterOrEqual(t, result, before)
	assert.LessOrEqual(t, result, after)
}
