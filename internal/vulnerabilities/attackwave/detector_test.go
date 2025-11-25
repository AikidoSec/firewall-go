package attackwave_test

import (
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/attackwave"
	"github.com/stretchr/testify/assert"
)

func TestDetectorCheck(t *testing.T) {
	t.Helper()

	t.Run("returns false when context is nil", func(t *testing.T) {
		t.Helper()
		detector := attackwave.NewDetector(&attackwave.Options{
			AttackWaveThreshold: 3,
			AttackWaveTimeFrame: 60 * time.Second,
		})

		result := detector.Check(nil)
		assert.False(t, result)
	})

	t.Run("returns false when remote address is empty", func(t *testing.T) {
		t.Helper()
		detector := attackwave.NewDetector(&attackwave.Options{
			AttackWaveThreshold: 3,
			AttackWaveTimeFrame: 60 * time.Second,
		})

		ctx := &request.Context{}
		result := detector.Check(ctx)
		assert.False(t, result)
	})

	t.Run("returns false for non-suspicious requests", func(t *testing.T) {
		t.Helper()
		detector := attackwave.NewDetector(&attackwave.Options{
			AttackWaveThreshold: 3,
			AttackWaveTimeFrame: 60 * time.Second,
		})

		ip := "192.168.1.1"
		ctx := &request.Context{
			RemoteAddress: &ip,
			Method:        "GET",
			Route:         "/api/users",
		}

		result := detector.Check(ctx)
		assert.False(t, result)
	})

	t.Run("detects attack wave after threshold is exceeded", func(t *testing.T) {
		t.Helper()
		detector := attackwave.NewDetector(&attackwave.Options{
			AttackWaveThreshold: 3,
			AttackWaveTimeFrame: 60 * time.Second,
		})

		ip := "192.168.1.1"
		ctx := &request.Context{
			RemoteAddress: &ip,
			Method:        "BADMETHOD", // Suspicious method
			Route:         "/api/users",
		}

		// First two checks should return false
		result := detector.Check(ctx)
		assert.False(t, result, "First suspicious request should not trigger")

		result = detector.Check(ctx)
		assert.False(t, result, "Second suspicious request should not trigger")

		// Third check should return true (threshold reached)
		result = detector.Check(ctx)
		assert.True(t, result, "Third suspicious request should trigger attack wave")
	})

	t.Run("tracks different IPs separately", func(t *testing.T) {
		t.Helper()
		detector := attackwave.NewDetector(&attackwave.Options{
			AttackWaveThreshold: 3,
			AttackWaveTimeFrame: 60 * time.Second,
		})

		ip1 := "192.168.1.1"
		ip2 := "192.168.1.2"

		ctx1 := &request.Context{
			RemoteAddress: &ip1,
			Route:         "/.git/config", // Suspicious path
		}

		ctx2 := &request.Context{
			RemoteAddress: &ip2,
			Route:         "/.env", // Suspicious path
		}

		// IP1: 2 requests
		detector.Check(ctx1)
		detector.Check(ctx1)

		// IP2: 2 requests
		detector.Check(ctx2)
		detector.Check(ctx2)

		// Neither should trigger yet
		result1 := detector.Check(ctx1)
		assert.True(t, result1, "IP1 should trigger on third request")

		result2 := detector.Check(ctx2)
		assert.True(t, result2, "IP2 should trigger on third request")
	})
}
