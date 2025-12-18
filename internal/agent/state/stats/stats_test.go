package stats

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOnRequest(t *testing.T) {
	t.Run("increments requests count", func(t *testing.T) {
		stats := New()

		stats.OnRequest()

		data := stats.GetAndClear()

		assert.Equal(t, 1, data.Requests.Total, "requests should be incremented to 1")
	})

	t.Run("increments Requests count multiple times", func(t *testing.T) {
		stats := New()

		stats.OnRequest()
		stats.OnRequest()
		stats.OnRequest()

		data := stats.GetAndClear()

		assert.Equal(t, 3, data.Requests.Total, "requests should be incremented to 3")
	})
}

func TestOnAttackDetected(t *testing.T) {
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
			stats := New()

			for i := 0; i < tt.calls; i++ {
				stats.OnAttackDetected(tt.blocked)
			}

			data := stats.GetAndClear()

			assert.Equal(t, tt.expectedAttacks, data.Requests.AttacksDetected.Total, "Attacks count should match")
			assert.Equal(t, tt.expectedAttacksBlocked, data.Requests.AttacksDetected.Blocked, "AttacksBlocked count should match")
		})
	}
}

func TestOnSinkStats(t *testing.T) {
	t.Run("stores stats for new sink", func(t *testing.T) {
		stats := New()

		sink := &aikido_types.MonitoredSinkTimings{
			AttacksDetected: aikido_types.AttacksDetected{
				Total:   5,
				Blocked: 2,
			},
			InterceptorThrewError: 1,
			WithoutContext:        3,
			Total:                 10001, // Above minimum threshold
			Timings:               []int64{1000000, 2000000},
		}

		stats.OnSinkStats("database", sink)
		data := stats.GetAndClear()

		require.Contains(t, data.Sinks, "database", "sink should be stored")
		sinkStats := data.Sinks["database"]
		assert.Equal(t, 5, sinkStats.AttacksDetected.Total)
		assert.Equal(t, 2, sinkStats.AttacksDetected.Blocked)
		assert.Equal(t, 1, sinkStats.InterceptorThrewError)
		assert.Equal(t, 3, sinkStats.WithoutContext)
		assert.Equal(t, 10001, sinkStats.Total)
		assert.Len(t, sinkStats.CompressedTimings, 1)
		assert.Equal(t, 1.5, sinkStats.CompressedTimings[0].AverageInMS)
	})

	t.Run("accumulates stats for existing sink", func(t *testing.T) {
		stats := New()

		// Add initial stats
		initialSink := &aikido_types.MonitoredSinkTimings{
			AttacksDetected: aikido_types.AttacksDetected{
				Total:   3,
				Blocked: 1,
			},
			InterceptorThrewError: 2,
			WithoutContext:        1,
			Total:                 6000,
			Timings:               []int64{500000},
		}
		stats.OnSinkStats("database", initialSink)

		// Add additional stats
		additionalSink := &aikido_types.MonitoredSinkTimings{
			AttacksDetected: aikido_types.AttacksDetected{
				Total:   4,
				Blocked: 2,
			},
			InterceptorThrewError: 1,
			WithoutContext:        2,
			Total:                 4001,
			Timings:               []int64{1000000, 2000000},
		}
		stats.OnSinkStats("database", additionalSink)

		data := stats.GetAndClear()

		require.Contains(t, data.Sinks, "database", "sink should be stored")
		sinkStats := data.Sinks["database"]
		assert.Equal(t, 7, sinkStats.AttacksDetected.Total, "AttacksDetected.Total should be accumulated (3+4)")
		assert.Equal(t, 3, sinkStats.AttacksDetected.Blocked, "AttacksDetected.Blocked should be accumulated (1+2)")
		assert.Equal(t, 3, sinkStats.InterceptorThrewError, "InterceptorThrewError should be accumulated (2+1)")
		assert.Equal(t, 3, sinkStats.WithoutContext, "WithoutContext should be accumulated (1+2)")
		assert.Equal(t, 10001, sinkStats.Total, "Total should be accumulated (6000+4001)")
		assert.Len(t, sinkStats.CompressedTimings, 1)
	})

	t.Run("handles multiple sinks", func(t *testing.T) {
		stats := New()

		stats1 := &aikido_types.MonitoredSinkTimings{
			AttacksDetected: aikido_types.AttacksDetected{
				Total:   2,
				Blocked: 1,
			},
			Total: 10001, // Above minimum threshold
		}

		stats2 := &aikido_types.MonitoredSinkTimings{
			AttacksDetected: aikido_types.AttacksDetected{
				Total:   3,
				Blocked: 2,
			},
			Total: 10002, // Above minimum threshold
		}

		stats.OnSinkStats("database", stats1)
		stats.OnSinkStats("http", stats2)

		data := stats.GetAndClear()

		require.Contains(t, data.Sinks, "database", "database sink should be stored")
		require.Contains(t, data.Sinks, "http", "http sink should be stored")

		dbStats := data.Sinks["database"]
		assert.Equal(t, 2, dbStats.AttacksDetected.Total)
		assert.Equal(t, 1, dbStats.AttacksDetected.Blocked)
		assert.Equal(t, 10001, dbStats.Total)

		httpStats := data.Sinks["http"]
		assert.Equal(t, 3, httpStats.AttacksDetected.Total)
		assert.Equal(t, 2, httpStats.AttacksDetected.Blocked)
		assert.Equal(t, 10002, httpStats.Total)
	})

	t.Run("filters sinks below minimum threshold", func(t *testing.T) {
		stats := New()

		// Sink with total below minimum threshold should not appear in results
		lowStats := &aikido_types.MonitoredSinkTimings{
			AttacksDetected: aikido_types.AttacksDetected{
				Total:   5,
				Blocked: 2,
			},
			Total: 5000, // Below minimum threshold of 10000
		}

		// Sink with total above minimum threshold should appear
		highStats := &aikido_types.MonitoredSinkTimings{
			AttacksDetected: aikido_types.AttacksDetected{
				Total:   3,
				Blocked: 1,
			},
			Total: 15000, // Above minimum threshold
		}

		stats.OnSinkStats("low", lowStats)
		stats.OnSinkStats("high", highStats)

		data := stats.GetAndClear()

		assert.NotContains(t, data.Sinks, "low", "sink below threshold should not be stored")
		require.Contains(t, data.Sinks, "high", "sink above threshold should be stored")

		highSinkStats := data.Sinks["high"]
		assert.Equal(t, 3, highSinkStats.AttacksDetected.Total)
		assert.Equal(t, 1, highSinkStats.AttacksDetected.Blocked)
		assert.Equal(t, 15000, highSinkStats.Total)
	})

	t.Run("appends timings correctly", func(t *testing.T) {
		stats := New()

		// Add initial timings
		initialSink := &aikido_types.MonitoredSinkTimings{
			Timings: []int64{1000000, 2000000},
			Total:   10001, // Above minimum threshold
		}
		stats.OnSinkStats("sink", initialSink)

		// Add more timings
		additionalSink := &aikido_types.MonitoredSinkTimings{
			Timings: []int64{3000000, 4000000, 5000000},
			Total:   10002, // Above minimum threshold
		}
		stats.OnSinkStats("sink", additionalSink)

		data := stats.GetAndClear()

		require.Contains(t, data.Sinks, "sink", "sink should be stored")
		sinkStats := data.Sinks["sink"]
		assert.Equal(t, 20003, sinkStats.Total, "Total should be accumulated")
		assert.Len(t, sinkStats.CompressedTimings, 1)
		// Average of [1000000, 2000000, 3000000, 4000000, 5000000] = 3.0
		assert.Equal(t, 3.0, sinkStats.CompressedTimings[0].AverageInMS, "Average should be calculated from all timings")
	})
}

func TestOnRateLimited(t *testing.T) {
	t.Run("increments rate limited count", func(t *testing.T) {
		stats := New()

		stats.OnRateLimit()

		data := stats.GetAndClear()

		assert.Equal(t, 1, data.Requests.RateLimited, "rate limited should be incremented to 1")
	})

	t.Run("increments rate limited count multiple times", func(t *testing.T) {
		stats := New()

		stats.OnRateLimit()
		stats.OnRateLimit()
		stats.OnRateLimit()

		data := stats.GetAndClear()

		assert.Equal(t, 3, data.Requests.RateLimited, "rate limited should be incremented to 3")
	})
}
