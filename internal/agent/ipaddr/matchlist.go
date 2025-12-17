package ipaddr

import (
	"log/slog"

	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/seancfoley/ipaddress-go/ipaddr"
)

type MatchList struct {
	Description string
	TrieV4      *ipaddr.IPv4AddressTrie
	TrieV6      *ipaddr.IPv6AddressTrie
}

func (list *MatchList) Matches(ip *ipaddr.IPAddress) bool {
	if list.TrieV4 == nil || list.TrieV6 == nil {
		return false
	}

	if (ip.IsIPv4() && list.TrieV4.ElementContains(ip.ToIPv4())) ||
		(ip.IsIPv6() && list.TrieV6.ElementContains(ip.ToIPv6())) {
		return true
	}

	return false
}

func BuildMatchList(name, description string, ipsList []string) MatchList {
	ipBlocklist := MatchList{
		Description: description,
		TrieV4:      &ipaddr.IPv4AddressTrie{},
		TrieV6:      &ipaddr.IPv6AddressTrie{},
	}

	for _, ip := range ipsList {
		ipAddress, err := ipaddr.NewIPAddressString(ip).ToAddress()
		if err != nil {
			log.Info("Invalid address", slog.String("name", name), slog.String("ip", ip))
			continue
		}

		if ipAddress.IsIPv4() {
			ipBlocklist.TrieV4.Add(ipAddress.ToIPv4())
		} else if ipAddress.IsIPv6() {
			ipBlocklist.TrieV6.Add(ipAddress.ToIPv6())
		}
	}

	return ipBlocklist
}

func Parse(ip string) (*ipaddr.IPAddress, error) {
	return ipaddr.NewIPAddressString(ip).ToAddress()
}
