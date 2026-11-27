//go:build sink_bench

package zeninternals

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWaitForCompilation(t *testing.T) {
	require.NoError(t, Init())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, WaitForCompilation(ctx))
	require.True(t, hasCompileFinished())
}

func TestWaitForCompilationCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, WaitForCompilation(ctx), context.Canceled)
}
