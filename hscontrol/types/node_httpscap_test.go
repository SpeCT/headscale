package types

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestTailNodeHTTPSCapability verifies that the self node carries
// [tailcfg.CapabilityHTTPS] exactly when dns.https_certs is enabled. The
// `tailscale serve` CLI refuses to configure an HTTPS listener without it.
func TestTailNodeHTTPSCapability(t *testing.T) {
	t.Parallel()

	ipv4 := netip.MustParseAddr("100.64.0.1")
	node := (&Node{
		ID:        1,
		Hostname:  "node1",
		GivenName: "node1",
		IPv4:      &ipv4,
		Hostinfo:  &tailcfg.Hostinfo{OS: "linux"},
	}).View()

	noRoutes := func(NodeID) []netip.Prefix { return nil }

	for _, enabled := range []bool{false, true} {
		cfg := &Config{BaseDomain: "tailnet.example.com"}
		cfg.DNSConfig.HTTPSCerts.Enabled = enabled

		tn, err := node.TailNode(tailcfg.CurrentCapabilityVersion, noRoutes, cfg, nil)
		require.NoError(t, err)

		_, has := tn.CapMap[tailcfg.CapabilityHTTPS]
		assert.Equal(t, enabled, has, "CapabilityHTTPS present=%v, want %v", has, enabled)
		assert.Equal(t, "node1.tailnet.example.com.", tn.Name)
	}
}
