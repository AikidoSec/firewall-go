package ipaddr

import (
	"log/slog"
	"net/netip"

	"github.com/AikidoSec/firewall-go/internal/log"
	"go4.org/netipx"
)

type MatchList struct {
	Description string
	ipSet       *netipx.IPSet
	Count       int
}

func (list *MatchList) Matches(ip netip.Addr) bool {
	if list.ipSet == nil {
		return false
	}

	return list.ipSet.Contains(ip)
}

func BuildMatchList(name, description string, ipsList []string) MatchList {
	count := 0
	builder := &netipx.IPSetBuilder{}

	for _, ip := range ipsList {
		prefix, err := netip.ParsePrefix(ip)
		if err == nil {
			builder.AddPrefix(prefix)
			count++
			continue
		}

		parsedIP, err := netip.ParseAddr(ip)
		if err == nil {
			builder.Add(parsedIP)
			count++
			continue
		}

		log.Info("Invalid address", slog.String("name", name), slog.String("ip", ip))
	}

	ipSet, err := builder.IPSet()
	if err != nil {
		log.Warn("Failed to build IP set", slog.String("name", name), slog.Any("error", err))
		return MatchList{
			Description: description,
			ipSet:       nil,
			Count:       0,
		}
	}

	return MatchList{
		Description: description,
		ipSet:       ipSet,
		Count:       count,
	}
}

func Parse(ip string) (netip.Addr, error) {
	result, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Addr{}, err
	}

	if result.Is4In6() {
		return result.Unmap(), nil
	}

	return result, nil
}
