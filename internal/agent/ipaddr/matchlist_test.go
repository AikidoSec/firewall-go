package ipaddr

import (
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildMatchlist(t *testing.T) {
	t.Run("builds IPv4 blocklist", func(t *testing.T) {
		ips := []string{"192.168.1.1", "10.0.0.0/8"}
		blocklist := BuildMatchList("test", "Test list", ips)

		assert.Equal(t, "Test list", blocklist.Description)
		assert.NotNil(t, blocklist.ipSet)
		assert.Equal(t, 2, blocklist.Count)
	})

	t.Run("builds IPv6 blocklist", func(t *testing.T) {
		ips := []string{"2001:db8::1", "2001:db8::/32"}
		blocklist := BuildMatchList("test", "IPv6 list", ips)

		assert.Equal(t, "IPv6 list", blocklist.Description)
		assert.NotNil(t, blocklist.ipSet)
		assert.Equal(t, 2, blocklist.Count)
	})

	t.Run("handles mixed IPv4 and IPv6", func(t *testing.T) {
		ips := []string{"192.168.1.1", "2001:db8::1"}
		blocklist := BuildMatchList("mixed", "Mixed list", ips)

		assert.Equal(t, "Mixed list", blocklist.Description)
		assert.NotNil(t, blocklist.ipSet)
		assert.Equal(t, 2, blocklist.Count)
	})

	t.Run("skips invalid IP addresses", func(t *testing.T) {
		ips := []string{"192.168.1.1", "not-an-ip", "10.0.0.1"}
		blocklist := BuildMatchList("test", "Test", ips)

		// Should not panic and should create ipSet
		assert.NotNil(t, blocklist.ipSet)
		// Only 2 valid IPs, "not-an-ip" should be skipped
		assert.Equal(t, 2, blocklist.Count)
	})

	t.Run("handles empty IP list", func(t *testing.T) {
		ips := []string{}
		blocklist := BuildMatchList("empty", "Empty list", ips)

		assert.Equal(t, "Empty list", blocklist.Description)
		assert.NotNil(t, blocklist.ipSet)
		assert.Equal(t, 0, blocklist.Count)
	})
}

func TestMatchList_Matches(t *testing.T) {
	t.Run("matches IPv4 address in blocklist", func(t *testing.T) {
		ips := []string{"192.168.1.1", "10.0.0.0/8"}
		blocklist := BuildMatchList("test", "Test list", ips)

		// Test exact match
		ip := netip.MustParseAddr("192.168.1.1")
		assert.True(t, blocklist.Matches(ip))

		// Test CIDR match
		ip = netip.MustParseAddr("10.5.5.5")
		assert.True(t, blocklist.Matches(ip))
	})

	t.Run("matches IPv6 address in blocklist", func(t *testing.T) {
		ips := []string{"2001:db8::1", "2001:db8::/32"}
		blocklist := BuildMatchList("test", "IPv6 list", ips)

		// Test exact match
		ip := netip.MustParseAddr("2001:db8::1")
		assert.True(t, blocklist.Matches(ip))

		// Test CIDR match
		ip = netip.MustParseAddr("2001:db8:1::1")
		assert.True(t, blocklist.Matches(ip))
	})

	t.Run("returns false for non-matching IP", func(t *testing.T) {
		ips := []string{"192.168.1.1", "10.0.0.0/8"}
		blocklist := BuildMatchList("test", "Test list", ips)

		ip := netip.MustParseAddr("172.16.0.1")
		assert.False(t, blocklist.Matches(ip))
	})

	t.Run("returns false when ipSet is nil", func(t *testing.T) {
		blocklist := MatchList{
			Description: "Empty list",
			ipSet:       nil,
		}

		ip := netip.MustParseAddr("192.168.1.1")
		assert.False(t, blocklist.Matches(ip))
	})

	t.Run("handles mixed IPv4 and IPv6 blocklist", func(t *testing.T) {
		ips := []string{"192.168.1.1", "2001:db8::1"}
		blocklist := BuildMatchList("mixed", "Mixed list", ips)

		// Test IPv4 match
		ipv4 := netip.MustParseAddr("192.168.1.1")
		assert.True(t, blocklist.Matches(ipv4))

		// Test IPv6 match
		ipv6 := netip.MustParseAddr("2001:db8::1")
		assert.True(t, blocklist.Matches(ipv6))

		// Test non-match
		ipNoMatch := netip.MustParseAddr("10.0.0.1")
		assert.False(t, blocklist.Matches(ipNoMatch))
	})
}

func TestMatchList_MappedIPv4(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		ip    string
		match bool
	}{
		{"mapped CIDR", "::ffff:185.162.16.0/120", "185.162.16.188", true},
		{"mapped CIDR first address", "::ffff:185.162.16.0/120", "185.162.16.0", true},
		{"mapped CIDR last address", "::ffff:185.162.16.0/120", "185.162.16.255", true},
		{"mapped CIDR below range", "::ffff:185.162.16.0/120", "185.162.15.255", false},
		{"mapped CIDR above range", "::ffff:185.162.16.0/120", "185.162.17.0", false},
		{"mapped CIDR with host bits", "::ffff:185.162.16.188/120", "185.162.16.1", true},
		{"mapped exact address", "::ffff:185.162.16.188", "185.162.16.188", true},
		{"mapped exact address miss", "::ffff:185.162.16.188", "185.162.16.189", false},
		{"mapped host prefix", "::ffff:185.162.16.188/128", "185.162.16.188", true},
		{"mapped host prefix miss", "::ffff:185.162.16.188/128", "185.162.16.189", false},
		{"entire mapped range", "::ffff:0:0/96", "185.162.16.188", true},
		{"broader IPv6 range", "::fffe:0:0/95", "185.162.16.188", true},
		{"IPv4 CIDR", "185.162.16.0/24", "185.162.16.188", true},
		{"IPv4 exact address", "185.162.16.188", "185.162.16.188", true},
		{"unrelated IPv6 range", "2001:db8::/32", "185.162.16.188", false},
		{"IPv4-compatible is not mapped", "::185.162.16.188/128", "185.162.16.188", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list := BuildMatchList("test", "Mapped IPv4 list", []string{tt.entry})
			for _, input := range []string{tt.ip, "::ffff:" + tt.ip} {
				assert.Equal(t, tt.match, list.Matches(netip.MustParseAddr(input)), input)
			}
		})
	}
}

func TestParse(t *testing.T) {
	t.Run("parses valid IPv4 address", func(t *testing.T) {
		ip, err := Parse("192.168.1.1")
		require.NoError(t, err)
		assert.True(t, ip.Is4())
		assert.Equal(t, "192.168.1.1", ip.String())
	})

	t.Run("parses valid IPv6 address", func(t *testing.T) {
		ip, err := Parse("2001:db8::1")
		require.NoError(t, err)
		assert.True(t, ip.Is6())
		assert.Equal(t, "2001:db8::1", ip.String())
	})

	t.Run("parses and unmaps IPv4-mapped IPv6 address", func(t *testing.T) {
		ip, err := Parse("::ffff:192.168.1.1")
		require.NoError(t, err)
		assert.True(t, ip.Is4(), "Should be unmapped to IPv4")
		assert.Equal(t, "192.168.1.1", ip.String())
	})

	t.Run("strips the zone from a zoned link-local IPv6 address", func(t *testing.T) {
		ip, err := Parse("fe80::1%eth0")
		require.NoError(t, err)
		assert.Empty(t, ip.Zone())
		assert.Equal(t, "fe80::1", ip.String())
	})

	t.Run("strips the zone from a zoned loopback IPv6 address", func(t *testing.T) {
		ip, err := Parse("::1%lo")
		require.NoError(t, err)
		assert.Empty(t, ip.Zone())
		assert.Equal(t, "::1", ip.String())
	})

	t.Run("returns error for invalid IP address", func(t *testing.T) {
		_, err := Parse("not-an-ip")
		assert.Error(t, err)
	})

	t.Run("returns error for malformed IP", func(t *testing.T) {
		_, err := Parse("192.168.1.256")
		assert.Error(t, err)
	})

	t.Run("returns error for CIDR notation", func(t *testing.T) {
		// Parse is for addresses only, not prefixes
		_, err := Parse("192.168.1.0/24")
		assert.Error(t, err)
	})
}

func randomIPv4(r *rand.Rand) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))})
}

func randomIPv6(r *rand.Rand) netip.Addr {
	var b [16]byte
	r.Read(b[:])
	return netip.AddrFrom16(b)
}

// generateIPList approximates a real block/allow list (e.g. geoip-sourced):
// almost entirely IPv4 CIDR ranges of varying prefix length, with a small
// share of IPv6 CIDRs and single addresses.
func generateIPList(n int) []string {
	r := rand.New(rand.NewSource(42))
	ips := make([]string, n)
	for i := range ips {
		switch roll := r.Float64(); {
		case roll < 0.90:
			ips[i] = fmt.Sprintf("%s/%d", randomIPv4(r), 13+r.Intn(20))
		case roll < 0.95:
			ips[i] = fmt.Sprintf("%s/%d", randomIPv6(r), 32+r.Intn(96))
		case roll < 0.97:
			ips[i] = randomIPv6(r).String()
		default:
			ips[i] = randomIPv4(r).String()
		}
	}
	return ips
}

func pickMissAddr(list MatchList, gen func(*rand.Rand) netip.Addr, seed int64) netip.Addr {
	r := rand.New(rand.NewSource(seed))
	for i := 0; i < 100_000; i++ {
		if addr := gen(r); !list.Matches(addr) {
			return addr
		}
	}
	panic("could not find an address outside the generated list")
}

var benchListSizes = []int{1_000, 10_000, 100_000, 1_000_000}

func BenchmarkBuildMatchList(b *testing.B) {
	for _, n := range benchListSizes {
		ips := generateIPList(n)
		b.Run(fmt.Sprintf("%d_entries", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				BuildMatchList("bench", "benchmark list", ips)
			}
		})
	}
}

func BenchmarkMatchList_Matches(b *testing.B) {
	for _, n := range benchListSizes {
		ips := generateIPList(n)
		list := BuildMatchList("bench", "benchmark list", ips)

		hit := netip.MustParseAddr(strings.SplitN(ips[0], "/", 2)[0])
		missV4 := pickMissAddr(list, randomIPv4, 1)
		missV6 := pickMissAddr(list, randomIPv6, 2)

		b.Run(fmt.Sprintf("%d_entries/hit", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				list.Matches(hit)
			}
		})

		b.Run(fmt.Sprintf("%d_entries/miss_ipv4", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				list.Matches(missV4)
			}
		})

		b.Run(fmt.Sprintf("%d_entries/miss_ipv6", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				list.Matches(missV6)
			}
		})
	}
}
