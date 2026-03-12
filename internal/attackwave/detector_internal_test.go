package attackwave

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDetector(t *testing.T) {
	t.Run("with nil options uses defaults", func(t *testing.T) {
		detector := NewDetector(nil)

		require.NotNil(t, detector)
		assert.Equal(t, 15, detector.attackWaveThreshold)
		assert.Equal(t, 60*time.Second, detector.attackWaveTimeFrame)
		assert.Equal(t, 20*time.Minute, detector.minTimeBetweenReports)
	})

	t.Run("with custom options", func(t *testing.T) {
		opts := &Options{
			AttackWaveThreshold:   10,
			AttackWaveTimeFrame:   30 * time.Second,
			MinTimeBetweenReports: 1 * time.Second,
		}
		detector := NewDetector(opts)

		require.NotNil(t, detector)
		assert.Equal(t, 10, detector.attackWaveThreshold)
		assert.Equal(t, 30*time.Second, detector.attackWaveTimeFrame)
		assert.Equal(t, 1*time.Second, detector.minTimeBetweenReports)
	})
}
