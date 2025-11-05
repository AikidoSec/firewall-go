package agent

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreStats(t *testing.T) {
	t.Run("increments Requests count", func(t *testing.T) {
		// Reset stats before test
		globals.StatsData.StatsMutex.Lock()
		globals.StatsData.Requests = 0
		globals.StatsData.StatsMutex.Unlock()

		storeStats()

		globals.StatsData.StatsMutex.Lock()
		defer globals.StatsData.StatsMutex.Unlock()

		assert.Equal(t, 1, globals.StatsData.Requests, "Requests should be incremented to 1")
	})

	t.Run("increments Requests count multiple times", func(t *testing.T) {
		// Reset stats before test
		globals.StatsData.StatsMutex.Lock()
		globals.StatsData.Requests = 0
		globals.StatsData.StatsMutex.Unlock()

		storeStats()
		storeStats()
		storeStats()

		globals.StatsData.StatsMutex.Lock()
		defer globals.StatsData.StatsMutex.Unlock()

		assert.Equal(t, 3, globals.StatsData.Requests, "Requests should be incremented to 3")
	})
}

func TestStoreAttackStats(t *testing.T) {
	tests := []struct {
		name                   string
		blocked                bool
		initialAttacks         int
		initialAttacksBlocked  int
		calls                  int
		expectedAttacks        int
		expectedAttacksBlocked int
	}{
		{
			name:                   "increments Attacks when not blocked",
			blocked:                false,
			initialAttacks:         0,
			initialAttacksBlocked:  0,
			calls:                  1,
			expectedAttacks:        1,
			expectedAttacksBlocked: 0,
		},
		{
			name:                   "increments both Attacks and AttacksBlocked when blocked",
			blocked:                true,
			initialAttacks:         0,
			initialAttacksBlocked:  0,
			calls:                  1,
			expectedAttacks:        1,
			expectedAttacksBlocked: 1,
		},
		{
			name:                   "increments from existing values",
			blocked:                true,
			initialAttacks:         5,
			initialAttacksBlocked:  2,
			calls:                  1,
			expectedAttacks:        6,
			expectedAttacksBlocked: 3,
		},
		{
			name:                   "multiple blocked attacks",
			blocked:                true,
			initialAttacks:         0,
			initialAttacksBlocked:  0,
			calls:                  3,
			expectedAttacks:        3,
			expectedAttacksBlocked: 3,
		},
		{
			name:                   "multiple non-blocked attacks",
			blocked:                false,
			initialAttacks:         0,
			initialAttacksBlocked:  0,
			calls:                  2,
			expectedAttacks:        2,
			expectedAttacksBlocked: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset stats before test
			globals.StatsData.StatsMutex.Lock()
			globals.StatsData.Attacks = tt.initialAttacks
			globals.StatsData.AttacksBlocked = tt.initialAttacksBlocked
			globals.StatsData.StatsMutex.Unlock()

			for i := 0; i < tt.calls; i++ {
				storeAttackStats(tt.blocked)
			}

			globals.StatsData.StatsMutex.Lock()
			defer globals.StatsData.StatsMutex.Unlock()

			assert.Equal(t, tt.expectedAttacks, globals.StatsData.Attacks, "Attacks count should match")
			assert.Equal(t, tt.expectedAttacksBlocked, globals.StatsData.AttacksBlocked, "AttacksBlocked count should match")
		})
	}
}

func TestStoreSinkStats(t *testing.T) {
	t.Run("stores stats for new sink", func(t *testing.T) {
		// Reset stats before test
		globals.StatsData.StatsMutex.Lock()
		globals.StatsData.MonitoredSinkTimings = make(map[string]aikido_types.MonitoredSinkTimings)
		globals.StatsData.StatsMutex.Unlock()

		stats := &aikido_types.MonitoredSinkTimings{
			AttacksDetected: aikido_types.AttacksDetected{
				Total:   5,
				Blocked: 2,
			},
			InterceptorThrewError: 1,
			WithoutContext:        3,
			Total:                 10,
			Timings:               []int64{1000000, 2000000},
		}

		storeSinkStats("database", stats)

		globals.StatsData.StatsMutex.Lock()
		defer globals.StatsData.StatsMutex.Unlock()

		require.Contains(t, globals.StatsData.MonitoredSinkTimings, "database", "sink should be stored")
		sinkStats := globals.StatsData.MonitoredSinkTimings["database"]
		assert.Equal(t, 5, sinkStats.AttacksDetected.Total)
		assert.Equal(t, 2, sinkStats.AttacksDetected.Blocked)
		assert.Equal(t, 1, sinkStats.InterceptorThrewError)
		assert.Equal(t, 3, sinkStats.WithoutContext)
		assert.Equal(t, 10, sinkStats.Total)
		assert.Equal(t, []int64{1000000, 2000000}, sinkStats.Timings)
	})

	t.Run("accumulates stats for existing sink", func(t *testing.T) {
		// Reset stats before test
		globals.StatsData.StatsMutex.Lock()
		globals.StatsData.MonitoredSinkTimings = make(map[string]aikido_types.MonitoredSinkTimings)
		globals.StatsData.MonitoredSinkTimings["database"] = aikido_types.MonitoredSinkTimings{
			AttacksDetected: aikido_types.AttacksDetected{
				Total:   3,
				Blocked: 1,
			},
			InterceptorThrewError: 2,
			WithoutContext:        1,
			Total:                 5,
			Timings:               []int64{500000},
		}
		globals.StatsData.StatsMutex.Unlock()

		stats := &aikido_types.MonitoredSinkTimings{
			AttacksDetected: aikido_types.AttacksDetected{
				Total:   4,
				Blocked: 2,
			},
			InterceptorThrewError: 1,
			WithoutContext:        2,
			Total:                 7,
			Timings:               []int64{1000000, 2000000},
		}

		storeSinkStats("database", stats)

		globals.StatsData.StatsMutex.Lock()
		defer globals.StatsData.StatsMutex.Unlock()

		sinkStats := globals.StatsData.MonitoredSinkTimings["database"]
		assert.Equal(t, 7, sinkStats.AttacksDetected.Total, "AttacksDetected.Total should be accumulated (3+4)")
		assert.Equal(t, 3, sinkStats.AttacksDetected.Blocked, "AttacksDetected.Blocked should be accumulated (1+2)")
		assert.Equal(t, 3, sinkStats.InterceptorThrewError, "InterceptorThrewError should be accumulated (2+1)")
		assert.Equal(t, 3, sinkStats.WithoutContext, "WithoutContext should be accumulated (1+2)")
		assert.Equal(t, 12, sinkStats.Total, "Total should be accumulated (5+7)")
		assert.Equal(t, []int64{500000, 1000000, 2000000}, sinkStats.Timings, "Timings should be appended")
	})

	t.Run("handles multiple sinks", func(t *testing.T) {
		// Reset stats before test
		globals.StatsData.StatsMutex.Lock()
		globals.StatsData.MonitoredSinkTimings = make(map[string]aikido_types.MonitoredSinkTimings)
		globals.StatsData.StatsMutex.Unlock()

		stats1 := &aikido_types.MonitoredSinkTimings{
			AttacksDetected: aikido_types.AttacksDetected{
				Total:   2,
				Blocked: 1,
			},
			Total: 5,
		}

		stats2 := &aikido_types.MonitoredSinkTimings{
			AttacksDetected: aikido_types.AttacksDetected{
				Total:   3,
				Blocked: 2,
			},
			Total: 8,
		}

		storeSinkStats("database", stats1)
		storeSinkStats("http", stats2)

		globals.StatsData.StatsMutex.Lock()
		defer globals.StatsData.StatsMutex.Unlock()

		require.Contains(t, globals.StatsData.MonitoredSinkTimings, "database", "database sink should be stored")
		require.Contains(t, globals.StatsData.MonitoredSinkTimings, "http", "http sink should be stored")

		dbStats := globals.StatsData.MonitoredSinkTimings["database"]
		assert.Equal(t, 2, dbStats.AttacksDetected.Total)
		assert.Equal(t, 1, dbStats.AttacksDetected.Blocked)
		assert.Equal(t, 5, dbStats.Total)

		httpStats := globals.StatsData.MonitoredSinkTimings["http"]
		assert.Equal(t, 3, httpStats.AttacksDetected.Total)
		assert.Equal(t, 2, httpStats.AttacksDetected.Blocked)
		assert.Equal(t, 8, httpStats.Total)
	})

	t.Run("handles empty stats", func(t *testing.T) {
		// Reset stats before test
		globals.StatsData.StatsMutex.Lock()
		globals.StatsData.MonitoredSinkTimings = make(map[string]aikido_types.MonitoredSinkTimings)
		globals.StatsData.StatsMutex.Unlock()

		stats := &aikido_types.MonitoredSinkTimings{}

		storeSinkStats("empty", stats)

		globals.StatsData.StatsMutex.Lock()
		defer globals.StatsData.StatsMutex.Unlock()

		require.Contains(t, globals.StatsData.MonitoredSinkTimings, "empty", "sink should be stored even with empty stats")
		sinkStats := globals.StatsData.MonitoredSinkTimings["empty"]
		assert.Equal(t, 0, sinkStats.AttacksDetected.Total)
		assert.Equal(t, 0, sinkStats.AttacksDetected.Blocked)
		assert.Equal(t, 0, sinkStats.InterceptorThrewError)
		assert.Equal(t, 0, sinkStats.WithoutContext)
		assert.Equal(t, 0, sinkStats.Total)
		assert.Nil(t, sinkStats.Timings)
	})

	t.Run("appends timings correctly", func(t *testing.T) {
		// Reset stats before test
		globals.StatsData.StatsMutex.Lock()
		globals.StatsData.MonitoredSinkTimings = make(map[string]aikido_types.MonitoredSinkTimings)
		globals.StatsData.MonitoredSinkTimings["sink"] = aikido_types.MonitoredSinkTimings{
			Timings: []int64{1000000, 2000000},
		}
		globals.StatsData.StatsMutex.Unlock()

		stats := &aikido_types.MonitoredSinkTimings{
			Timings: []int64{3000000, 4000000, 5000000},
		}

		storeSinkStats("sink", stats)

		globals.StatsData.StatsMutex.Lock()
		defer globals.StatsData.StatsMutex.Unlock()

		sinkStats := globals.StatsData.MonitoredSinkTimings["sink"]
		assert.Equal(t, []int64{1000000, 2000000, 3000000, 4000000, 5000000}, sinkStats.Timings, "Timings should be appended")
	})
}
