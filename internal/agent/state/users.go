package state

import (
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
)

func (c *Collector) StoreUser(id string, username string, ip string) aikido_types.User {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := utils.GetTime()
	firstSeen := now

	if existing, exists := c.users[id]; exists {
		firstSeen = existing.FirstSeenAt
	}

	user := aikido_types.User{
		ID:            id,
		Name:          username,
		LastIpAddress: ip,
		FirstSeenAt:   firstSeen,
		LastSeenAt:    now,
	}
	c.users[id] = user
	return user
}

func (c *Collector) GetUsersAndClear() []aikido_types.User {
	c.mu.Lock()
	defer c.mu.Unlock()

	var result []aikido_types.User
	for _, user := range c.users {
		result = append(result, user)
	}

	c.users = make(map[string]aikido_types.User)
	return result
}
