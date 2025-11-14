package state

import "github.com/AikidoSec/firewall-go/internal/agent/aikido_types"

func (c *Collector) StoreHostname(domain string, port uint32) {
	if port == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.hostnames[domain]; !ok {
		c.hostnames[domain] = make(map[uint32]uint64)
	}

	c.hostnames[domain][port]++
}

func (c *Collector) GetAndClearHostnames() []aikido_types.Hostname {
	c.mu.Lock()
	defer c.mu.Unlock()

	var result []aikido_types.Hostname
	for domain := range c.hostnames {
		for port := range c.hostnames[domain] {
			result = append(result, aikido_types.Hostname{URL: domain, Port: port, Hits: c.hostnames[domain][port]})
		}
	}

	c.hostnames = make(map[string]map[uint32]uint64)
	return result
}
