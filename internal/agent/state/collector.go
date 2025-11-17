package state

import (
	"sync"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
)

type Collector struct {
	mu sync.Mutex

	// List of outgoing hostnames, their ports and number of hits, collected from the requests
	// [domain][port] = hits
	hostnames map[string]map[uint32]uint64

	// List of routes and their methods and count of calls collect from the requests
	// [route][method] = hits
	routes map[string]map[string]*aikido_types.Route
}

func NewCollector() *Collector {
	return &Collector{
		hostnames: make(map[string]map[uint32]uint64),
		routes:    make(map[string]map[string]*aikido_types.Route),
	}
}
