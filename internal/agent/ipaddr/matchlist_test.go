package ipaddr_test

import (
	"testing"

	ipaddrPkg "github.com/AikidoSec/firewall-go/internal/agent/ipaddr"
	"github.com/seancfoley/ipaddress-go/ipaddr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildMatchlist(t *testing.T) {
	t.Run("builds IPv4 blocklist", func(t *testing.T) {
		ips := []string{"192.168.1.1", "10.0.0.0/8"}
		blocklist := ipaddrPkg.BuildMatchList("test", "Test list", ips)

		assert.Equal(t, "Test list", blocklist.Description)
		assert.NotNil(t, blocklist.TrieV4)
		assert.NotNil(t, blocklist.TrieV6)
	})

	t.Run("builds IPv6 blocklist", func(t *testing.T) {
		ips := []string{"2001:db8::1", "2001:db8::/32"}
		blocklist := ipaddrPkg.BuildMatchList("test", "IPv6 list", ips)

		assert.Equal(t, "IPv6 list", blocklist.Description)
		assert.NotNil(t, blocklist.TrieV4)
		assert.NotNil(t, blocklist.TrieV6)
	})

	t.Run("handles mixed IPv4 and IPv6", func(t *testing.T) {
		ips := []string{"192.168.1.1", "2001:db8::1"}
		blocklist := ipaddrPkg.BuildMatchList("mixed", "Mixed list", ips)

		assert.Equal(t, "Mixed list", blocklist.Description)
		assert.NotNil(t, blocklist.TrieV4)
		assert.NotNil(t, blocklist.TrieV6)
	})

	t.Run("skips invalid IP addresses", func(t *testing.T) {
		ips := []string{"192.168.1.1", "not-an-ip", "10.0.0.1"}
		blocklist := ipaddrPkg.BuildMatchList("test", "Test", ips)

		// Should not panic and should create tries
		assert.NotNil(t, blocklist.TrieV4)
		assert.NotNil(t, blocklist.TrieV6)
	})

	t.Run("handles empty IP list", func(t *testing.T) {
		ips := []string{}
		blocklist := ipaddrPkg.BuildMatchList("empty", "Empty list", ips)

		assert.Equal(t, "Empty list", blocklist.Description)
		assert.NotNil(t, blocklist.TrieV4)
		assert.NotNil(t, blocklist.TrieV6)
	})
}

func TestMatchList_Matches(t *testing.T) {
	t.Run("matches IPv4 address in blocklist", func(t *testing.T) {
		ips := []string{"192.168.1.1", "10.0.0.0/8"}
		blocklist := ipaddrPkg.BuildMatchList("test", "Test list", ips)

		// Test exact match
		ip, err := ipaddr.NewIPAddressString("192.168.1.1").ToAddress()
		require.NoError(t, err)
		assert.True(t, blocklist.Matches(ip))

		// Test CIDR match
		ip, err = ipaddr.NewIPAddressString("10.5.5.5").ToAddress()
		require.NoError(t, err)
		assert.True(t, blocklist.Matches(ip))
	})

	t.Run("matches IPv6 address in blocklist", func(t *testing.T) {
		ips := []string{"2001:db8::1", "2001:db8::/32"}
		blocklist := ipaddrPkg.BuildMatchList("test", "IPv6 list", ips)

		// Test exact match
		ip, err := ipaddr.NewIPAddressString("2001:db8::1").ToAddress()
		require.NoError(t, err)
		assert.True(t, blocklist.Matches(ip))

		// Test CIDR match
		ip, err = ipaddr.NewIPAddressString("2001:db8:1::1").ToAddress()
		require.NoError(t, err)
		assert.True(t, blocklist.Matches(ip))
	})

	t.Run("returns false for non-matching IP", func(t *testing.T) {
		ips := []string{"192.168.1.1", "10.0.0.0/8"}
		blocklist := ipaddrPkg.BuildMatchList("test", "Test list", ips)

		ip, err := ipaddr.NewIPAddressString("172.16.0.1").ToAddress()
		require.NoError(t, err)
		assert.False(t, blocklist.Matches(ip))
	})

	t.Run("returns false when tries are nil", func(t *testing.T) {
		blocklist := ipaddrPkg.MatchList{
			Description: "Empty list",
			TrieV4:      nil,
			TrieV6:      nil,
		}

		ip, err := ipaddr.NewIPAddressString("192.168.1.1").ToAddress()
		require.NoError(t, err)
		assert.False(t, blocklist.Matches(ip))
	})

	t.Run("handles mixed IPv4 and IPv6 blocklist", func(t *testing.T) {
		ips := []string{"192.168.1.1", "2001:db8::1"}
		blocklist := ipaddrPkg.BuildMatchList("mixed", "Mixed list", ips)

		// Test IPv4 match
		ipv4, err := ipaddr.NewIPAddressString("192.168.1.1").ToAddress()
		require.NoError(t, err)
		assert.True(t, blocklist.Matches(ipv4))

		// Test IPv6 match
		ipv6, err := ipaddr.NewIPAddressString("2001:db8::1").ToAddress()
		require.NoError(t, err)
		assert.True(t, blocklist.Matches(ipv6))

		// Test non-match
		ipNoMatch, err := ipaddr.NewIPAddressString("10.0.0.1").ToAddress()
		require.NoError(t, err)
		assert.False(t, blocklist.Matches(ipNoMatch))
	})
}

func TestParse(t *testing.T) {
	t.Run("parses valid IPv4 address", func(t *testing.T) {
		ip, err := ipaddrPkg.Parse("192.168.1.1")
		assert.NoError(t, err)
		assert.NotNil(t, ip)
		assert.True(t, ip.IsIPv4())
		assert.Equal(t, "192.168.1.1", ip.String())
	})

	t.Run("parses valid IPv6 address", func(t *testing.T) {
		ip, err := ipaddrPkg.Parse("2001:db8::1")
		assert.NoError(t, err)
		assert.NotNil(t, ip)
		assert.True(t, ip.IsIPv6())
		assert.Equal(t, "2001:db8::1", ip.String())
	})

	t.Run("parses IPv4 CIDR notation", func(t *testing.T) {
		ip, err := ipaddrPkg.Parse("192.168.1.0/24")
		assert.NoError(t, err)
		assert.NotNil(t, ip)
		assert.True(t, ip.IsIPv4())
	})

	t.Run("parses IPv6 CIDR notation", func(t *testing.T) {
		ip, err := ipaddrPkg.Parse("2001:db8::/32")
		assert.NoError(t, err)
		assert.NotNil(t, ip)
		assert.True(t, ip.IsIPv6())
	})

	t.Run("returns error for invalid IP address", func(t *testing.T) {
		ip, err := ipaddrPkg.Parse("not-an-ip")
		assert.Error(t, err)
		assert.Nil(t, ip)
	})

	t.Run("returns error for malformed IP", func(t *testing.T) {
		ip, err := ipaddrPkg.Parse("192.168.1.256")
		assert.Error(t, err)
		assert.Nil(t, ip)
	})
}
