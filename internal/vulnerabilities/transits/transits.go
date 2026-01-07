package transits

import (
	"context"
	"sync"
)

var (
	mu                 sync.RWMutex
	examinePathFunc    func(op string, args []string, deferReporting bool) error
	examineCommandFunc func(ctx context.Context, op string, args []string) error
)

func SetTransits(
	examinePath func(op string, args []string, deferReporting bool) error,
	examineCommand func(ctx context.Context, op string, args []string) error,
) {
	mu.Lock()
	defer mu.Unlock()

	examinePathFunc = examinePath
	examineCommandFunc = examineCommand
}

func ExaminePath() func(op string, args []string, deferReporting bool) error {
	mu.RLock()
	defer mu.RUnlock()

	return examinePathFunc
}

func ExamineCommand() func(ctx context.Context, op string, args []string) error {
	mu.RLock()
	defer mu.RUnlock()

	return examineCommandFunc
}
