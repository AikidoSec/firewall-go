package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreUser(t *testing.T) {
	t.Cleanup(func() {
		GetUsersAndClear()
	})

	t.Run("stores a new user", func(t *testing.T) {
		GetUsersAndClear()

		user := storeUser("user1", "Alice", "1.2.3.4")

		assert.Equal(t, "user1", user.ID)
		assert.Equal(t, "Alice", user.Name)
		assert.Equal(t, "1.2.3.4", user.LastIpAddress)
		assert.NotZero(t, user.FirstSeenAt)
		assert.NotZero(t, user.LastSeenAt)
		assert.Equal(t, user.FirstSeenAt, user.LastSeenAt)
	})

	t.Run("preserves FirstSeenAt on update", func(t *testing.T) {
		GetUsersAndClear()

		first := storeUser("user1", "Alice", "1.2.3.4")
		second := storeUser("user1", "Alice Updated", "5.6.7.8")

		assert.Equal(t, first.FirstSeenAt, second.FirstSeenAt)
		assert.Equal(t, "Alice Updated", second.Name)
		assert.Equal(t, "5.6.7.8", second.LastIpAddress)
	})

	t.Run("stores multiple users independently", func(t *testing.T) {
		GetUsersAndClear()

		storeUser("user1", "Alice", "1.2.3.4")
		storeUser("user2", "Bob", "5.6.7.8")

		result := GetUsersAndClear()
		assert.Len(t, result, 2)
	})
}

func TestGetUsersAndClear(t *testing.T) {
	t.Cleanup(func() {
		GetUsersAndClear()
	})

	t.Run("returns empty slice when no users", func(t *testing.T) {
		GetUsersAndClear()

		result := GetUsersAndClear()
		assert.Empty(t, result)
	})

	t.Run("returns stored users and clears", func(t *testing.T) {
		GetUsersAndClear()

		storeUser("user1", "Alice", "1.2.3.4")
		storeUser("user2", "Bob", "5.6.7.8")

		result := GetUsersAndClear()
		require.Len(t, result, 2)

		// Verify cleared
		result2 := GetUsersAndClear()
		assert.Empty(t, result2)
	})
}
