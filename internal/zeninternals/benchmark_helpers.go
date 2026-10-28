//go:build sink_bench

package zeninternals

import (
	"context"
	"time"
)

// WaitForCompilation waits for the compiled module after Init has been called.
func WaitForCompilation(ctx context.Context) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if hasCompileFinished() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
