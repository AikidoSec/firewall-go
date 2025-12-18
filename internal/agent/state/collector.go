package state

import (
	"sync"
	"sync/atomic"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/state/stats"
)

type Collector struct {
	mu sync.Mutex

	// List of outgoing hostnames, their ports and number of hits, collected from the requests
	// [domain][port] = hits
	hostnames map[string]map[uint32]uint64

	// List of routes and their methods and count of calls collect from the requests
	// [route][method] = hits
	routes map[string]map[string]*aikido_types.Route

	middlewareInstalled atomic.Bool

	stats *stats.Stats
}

func NewCollector() *Collector {
	return &Collector{
		hostnames: make(map[string]map[uint32]uint64),
		routes:    make(map[string]map[string]*aikido_types.Route),
		stats:     stats.New(),
	}
}

func (c *Collector) SetMiddlewareInstalled(val bool) {
	c.middlewareInstalled.Store(val)
}

func (c *Collector) IsMiddlewareInstalled() bool {
	return c.middlewareInstalled.Load()
}

func (c *Collector) Stats() *stats.Stats {
	return c.stats
}
