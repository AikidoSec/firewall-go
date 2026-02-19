package stats

import (
	"testing"

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

func TestOnOperationCall(t *testing.T) {
	t.Run("registers new operation", func(t *testing.T) {
		stats := New()

		stats.OnOperationCall("database/sql.DB.Query", OperationKindSQL)

		data := stats.GetAndClear()

		require.Contains(t, data.Operations, "database/sql.DB.Query", "operation should be registered")
		opStats := data.Operations["database/sql.DB.Query"]
		assert.Equal(t, OperationKindSQL, opStats.Kind)
		assert.Equal(t, 1, opStats.Total)
		assert.Equal(t, 0, opStats.AttacksDetected.Total)
		assert.Equal(t, 0, opStats.AttacksDetected.Blocked)
	})

	t.Run("increments operation counter", func(t *testing.T) {
		stats := New()

		stats.OnOperationCall("database/sql.DB.Query", OperationKindSQL)
		stats.OnOperationCall("database/sql.DB.Query", OperationKindSQL)
		stats.OnOperationCall("database/sql.DB.Query", OperationKindSQL)

		data := stats.GetAndClear()

		require.Contains(t, data.Operations, "database/sql.DB.Query", "operation should be registered")
		opStats := data.Operations["database/sql.DB.Query"]
		assert.Equal(t, 3, opStats.Total, "operation counter should be incremented to 3")
	})

	t.Run("tracks multiple operations separately", func(t *testing.T) {
		stats := New()

		stats.OnOperationCall("database/sql.DB.Query", OperationKindSQL)
		stats.OnOperationCall("database/sql.DB.Exec", OperationKindSQL)
		stats.OnOperationCall("os/exec.Cmd.Run", OperationKindExec)

		data := stats.GetAndClear()

		assert.Len(t, data.Operations, 3, "should track 3 different operations")
		assert.Equal(t, 1, data.Operations["database/sql.DB.Query"].Total)
		assert.Equal(t, 1, data.Operations["database/sql.DB.Exec"].Total)
		assert.Equal(t, 1, data.Operations["os/exec.Cmd.Run"].Total)
	})
}

func TestOnOperationAttack(t *testing.T) {
	t.Run("tracks attack for registered operation", func(t *testing.T) {
		stats := New()

		stats.OnOperationCall("database/sql.DB.Query", OperationKindSQL)
		stats.OnOperationAttack("database/sql.DB.Query", false)

		data := stats.GetAndClear()

		require.Contains(t, data.Operations, "database/sql.DB.Query")
		opStats := data.Operations["database/sql.DB.Query"]
		assert.Equal(t, 1, opStats.AttacksDetected.Total)
		assert.Equal(t, 0, opStats.AttacksDetected.Blocked)
	})

	t.Run("tracks blocked attack for registered operation", func(t *testing.T) {
		stats := New()

		stats.OnOperationCall("database/sql.DB.Query", OperationKindSQL)
		stats.OnOperationAttack("database/sql.DB.Query", true)

		data := stats.GetAndClear()

		require.Contains(t, data.Operations, "database/sql.DB.Query")
		opStats := data.Operations["database/sql.DB.Query"]
		assert.Equal(t, 1, opStats.AttacksDetected.Total)
		assert.Equal(t, 1, opStats.AttacksDetected.Blocked)
	})

	t.Run("accumulates multiple attacks", func(t *testing.T) {
		stats := New()

		stats.OnOperationCall("database/sql.DB.Query", OperationKindSQL)
		stats.OnOperationAttack("database/sql.DB.Query", false)
		stats.OnOperationAttack("database/sql.DB.Query", true)
		stats.OnOperationAttack("database/sql.DB.Query", true)

		data := stats.GetAndClear()

		require.Contains(t, data.Operations, "database/sql.DB.Query")
		opStats := data.Operations["database/sql.DB.Query"]
		assert.Equal(t, 3, opStats.AttacksDetected.Total, "should track 3 total attacks")
		assert.Equal(t, 2, opStats.AttacksDetected.Blocked, "should track 2 blocked attacks")
	})

	t.Run("does not track attack for unregistered operation", func(t *testing.T) {
		stats := New()

		stats.OnOperationAttack("unregistered.Operation", true)

		data := stats.GetAndClear()

		assert.NotContains(t, data.Operations, "unregistered.Operation", "unregistered operation should not be tracked")
	})
}

func TestGetAndClearOperations(t *testing.T) {
	t.Run("clears operations after retrieval", func(t *testing.T) {
		stats := New()

		stats.OnOperationCall("database/sql.DB.Query", OperationKindSQL)
		stats.OnOperationAttack("database/sql.DB.Query", false)

		data1 := stats.GetAndClear()
		require.Contains(t, data1.Operations, "database/sql.DB.Query")

		data2 := stats.GetAndClear()
		assert.Empty(t, data2.Operations, "operations should be cleared after first GetAndClear")
	})

	t.Run("includes operations in result", func(t *testing.T) {
		stats := New()

		stats.OnOperationCall("database/sql.DB.Query", OperationKindSQL)
		stats.OnOperationCall("os/exec.Cmd.Run", OperationKindExec)

		data := stats.GetAndClear()

		assert.NotNil(t, data.Operations)
		assert.Len(t, data.Operations, 2, "should include both operations")
	})
}

func TestOnIPAddressMatches(t *testing.T) {
	t.Run("increments counters for each key", func(t *testing.T) {
		stats := New()

		stats.OnIPAddressMatches([]string{"tor/exit_nodes", "known_threat_actors/public_scanners"})

		data := stats.GetAndClear()

		assert.Equal(t, 1, data.IPAddresses.Breakdown["tor/exit_nodes"])
		assert.Equal(t, 1, data.IPAddresses.Breakdown["known_threat_actors/public_scanners"])
	})

	t.Run("accumulates across multiple calls", func(t *testing.T) {
		stats := New()

		stats.OnIPAddressMatches([]string{"tor/exit_nodes"})
		stats.OnIPAddressMatches([]string{"tor/exit_nodes"})
		stats.OnIPAddressMatches([]string{"tor/exit_nodes", "geoip/BE"})

		data := stats.GetAndClear()

		assert.Equal(t, 3, data.IPAddresses.Breakdown["tor/exit_nodes"])
		assert.Equal(t, 1, data.IPAddresses.Breakdown["geoip/BE"])
	})

	t.Run("clears after GetAndClear", func(t *testing.T) {
		stats := New()

		stats.OnIPAddressMatches([]string{"tor/exit_nodes"})
		stats.GetAndClear()

		data := stats.GetAndClear()

		assert.Empty(t, data.IPAddresses.Breakdown)
	})

	t.Run("no-op with empty keys", func(t *testing.T) {
		stats := New()

		stats.OnIPAddressMatches([]string{})
		stats.OnIPAddressMatches(nil)

		data := stats.GetAndClear()

		assert.Empty(t, data.IPAddresses.Breakdown)
	})
}

func TestOnUserAgentMatches(t *testing.T) {
	t.Run("increments counters for each key", func(t *testing.T) {
		stats := New()

		stats.OnUserAgentMatches([]string{"googlebot", "bingbot"})

		data := stats.GetAndClear()

		assert.Equal(t, 1, data.UserAgents.Breakdown["googlebot"])
		assert.Equal(t, 1, data.UserAgents.Breakdown["bingbot"])
	})

	t.Run("accumulates across multiple calls", func(t *testing.T) {
		stats := New()

		stats.OnUserAgentMatches([]string{"googlebot"})
		stats.OnUserAgentMatches([]string{"googlebot", "bingbot"})

		data := stats.GetAndClear()

		assert.Equal(t, 2, data.UserAgents.Breakdown["googlebot"])
		assert.Equal(t, 1, data.UserAgents.Breakdown["bingbot"])
	})

	t.Run("clears after GetAndClear", func(t *testing.T) {
		stats := New()

		stats.OnUserAgentMatches([]string{"googlebot"})
		stats.GetAndClear()

		data := stats.GetAndClear()

		assert.Empty(t, data.UserAgents.Breakdown)
	})

	t.Run("no-op with empty keys", func(t *testing.T) {
		stats := New()

		stats.OnUserAgentMatches([]string{})
		stats.OnUserAgentMatches(nil)

		data := stats.GetAndClear()

		assert.Empty(t, data.UserAgents.Breakdown)
	})
}

func TestMultipleOperationKinds(t *testing.T) {
	t.Run("tracks different operation kinds separately", func(t *testing.T) {
		stats := New()

		stats.OnOperationCall("database/sql.DB.Query", OperationKindSQL)
		stats.OnOperationCall("net/http.Client.Do", OperationKindOutgoingHTTP)
		stats.OnOperationCall("os.OpenFile", OperationKindFileSystem)
		stats.OnOperationCall("os/exec.Cmd.Run", OperationKindExec)

		data := stats.GetAndClear()

		assert.Len(t, data.Operations, 4)
		assert.Equal(t, OperationKindSQL, data.Operations["database/sql.DB.Query"].Kind)
		assert.Equal(t, OperationKindOutgoingHTTP, data.Operations["net/http.Client.Do"].Kind)
		assert.Equal(t, OperationKindFileSystem, data.Operations["os.OpenFile"].Kind)
		assert.Equal(t, OperationKindExec, data.Operations["os/exec.Cmd.Run"].Kind)
	})
}
