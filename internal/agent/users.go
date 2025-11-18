package agent

import (
	"sync"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
)

var (
	users      = make(map[string]aikido_types.User)
	usersMutex sync.Mutex
)

func GetUserByID(userID string) *aikido_types.User {
	if userID == "" {
		return nil
	}

	usersMutex.Lock()
	defer usersMutex.Unlock()

	user, exists := users[userID]
	if !exists {
		return nil
	}
	return &user
}

func storeUser(id string, username string, ip string) {
	usersMutex.Lock()
	defer usersMutex.Unlock()

	if _, exists := users[id]; exists {
		users[id] = aikido_types.User{
			ID:            id,
			Name:          username,
			LastIpAddress: ip,
			FirstSeenAt:   users[id].FirstSeenAt,
			LastSeenAt:    utils.GetTime(),
		}
		return
	}

	users[id] = aikido_types.User{
		ID:            id,
		Name:          username,
		LastIpAddress: ip,
		FirstSeenAt:   utils.GetTime(),
		LastSeenAt:    utils.GetTime(),
	}
}

func GetUsersAndClear() []aikido_types.User {
	usersMutex.Lock()
	defer usersMutex.Unlock()

	var result []aikido_types.User
	for _, user := range users {
		result = append(result, user)
	}

	users = make(map[string]aikido_types.User)
	return result
}
