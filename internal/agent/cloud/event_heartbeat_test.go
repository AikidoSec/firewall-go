package cloud

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeAverage(t *testing.T) {
	tests := []struct {
		name     string
		times    []int64
		expected float64
	}{
		{
			name:     "empty slice returns 0",
			times:    []int64{},
			expected: 0,
		},
		{
			name:     "single value",
			times:    []int64{1000000},
			expected: 1.0,
		},
		{
			name:     "multiple values",
			times:    []int64{1000000, 2000000, 3000000},
			expected: 2.0,
		},
		{
			name:     "converts nanoseconds to milliseconds",
			times:    []int64{5000000}, // 5,000,000 nanoseconds = 5 milliseconds
			expected: 5.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := computeAverage(tt.times)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestComputePercentiles(t *testing.T) {
	tests := []struct {
		name     string
		times    []int64
		expected map[string]float64
	}{
		{
			name:  "empty slice returns zeros",
			times: []int64{},
			expected: map[string]float64{
				"P50": 0,
				"P90": 0,
				"P95": 0,
				"P99": 0,
			},
		},
		{
			name:  "single value",
			times: []int64{1000000},
			expected: map[string]float64{
				"P50": 1.0,
				"P90": 1.0,
				"P95": 1.0,
				"P99": 1.0,
			},
		},
		{
			name:  "sorts values before calculating percentiles",
			times: []int64{5000000, 1000000, 3000000, 2000000, 4000000},
			expected: map[string]float64{
				"P50": 3.0,
				"P90": 5.0, // int(0.9 * 5) = 4, which is index 4 (5th element)
				"P95": 5.0, // int(0.95 * 5) = 4, which is index 4 (5th element)
				"P99": 5.0, // int(0.99 * 5) = 4, which is index 4 (5th element)
			},
		},
		{
			name:  "converts nanoseconds to milliseconds",
			times: []int64{10000000}, // 10,000,000 ns = 10 ms
			expected: map[string]float64{
				"P50": 10.0,
				"P90": 10.0,
				"P95": 10.0,
				"P99": 10.0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := computePercentiles(tt.times)
			assert.Equal(t, tt.expected, result)
		})
	}

	t.Run("multiple values calculates percentiles correctly", func(t *testing.T) {
		// Create 100 values from 1ms to 100ms (in nanoseconds)
		times := make([]int64, 100)
		for i := 0; i < 100; i++ {
			times[i] = int64((i + 1) * 1000000)
		}

		result := computePercentiles(times)

		// P50 should be around 50ms
		assert.InDelta(t, 50.0, result["P50"], 1.0)
		// P90 should be around 90ms
		assert.InDelta(t, 90.0, result["P90"], 1.0)
		// P95 should be around 95ms
		assert.InDelta(t, 95.0, result["P95"], 1.0)
		// P99 should be around 99ms
		assert.InDelta(t, 99.0, result["P99"], 1.0)
	})

	t.Run("does not mutate input slice", func(t *testing.T) {
		times := []int64{5000000, 1000000, 3000000, 2000000, 4000000}
		original := make([]int64, len(times))
		copy(original, times)

		computePercentiles(times)

		// Verify the input slice remains unchanged
		assert.Equal(t, original, times)
	})
}
