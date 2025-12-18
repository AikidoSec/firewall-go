package ipaddr

import (
	"net/netip"
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

	t.Run("handles IPv4-mapped IPv6 addresses", func(t *testing.T) {
		ips := []string{"192.168.1.1", "10.0.0.1"}
		blocklist := BuildMatchList("test", "IPv4 list", ips)

		// Test IPv4-mapped IPv6 address - netipx handles this automatically
		// when we use Unmap() in Parse or use the unmapped address
		ipv4Mapped := netip.MustParseAddr("::ffff:192.168.1.1")
		// The IPSet should match unmapped addresses
		assert.True(t, blocklist.Matches(ipv4Mapped.Unmap()), "Unmapped IPv4-mapped address should match")

		// Test non-matching
		ipv4MappedNoMatch := netip.MustParseAddr("::ffff:172.16.0.1")
		assert.False(t, blocklist.Matches(ipv4MappedNoMatch.Unmap()), "Unmapped IPv4-mapped address should not match if not in list")

		// Test regular IPv4 address still works
		ipv4 := netip.MustParseAddr("192.168.1.1")
		assert.True(t, blocklist.Matches(ipv4))
	})
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
