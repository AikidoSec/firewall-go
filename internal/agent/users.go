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

func storeUser(id string, username string, ip string) aikido_types.User {
	usersMutex.Lock()
	defer usersMutex.Unlock()

	now := utils.GetTime()
	firstSeen := now

	if existing, exists := users[id]; exists {
		firstSeen = existing.FirstSeenAt
	}

	user := aikido_types.User{
		ID:            id,
		Name:          username,
		LastIpAddress: ip,
		FirstSeenAt:   firstSeen,
		LastSeenAt:    now,
	}
	users[id] = user
	return user
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
