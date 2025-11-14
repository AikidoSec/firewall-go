package agent

import (
	"sync"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
)

// List of outgoing hostnames, their ports and number of hits, collected from the requests
var (
	hostnames      = make(map[string]map[uint32]uint64)
	hostnamesMutex sync.Mutex
)

func storeDomain(domain string, port uint32) {
	if port == 0 {
		return
	}

	hostnamesMutex.Lock()
	defer hostnamesMutex.Unlock()

	if _, ok := hostnames[domain]; !ok {
		hostnames[domain] = make(map[uint32]uint64)
	}

	hostnames[domain][port]++
}

func GetAndClearHostnames() []aikido_types.Hostname {
	hostnamesMutex.Lock()
	defer hostnamesMutex.Unlock()

	var result []aikido_types.Hostname
	for domain := range hostnames {
		for port := range hostnames[domain] {
			result = append(result, aikido_types.Hostname{URL: domain, Port: port, Hits: hostnames[domain][port]})
		}
	}

	hostnames = make(map[string]map[uint32]uint64)
	return result
}
