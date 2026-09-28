package mapper

import (
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
)

func TestGenerateDNSConfigCertDomains(t *testing.T) {
	t.Parallel()

	baseDomain := "tailnet.example.com"
	ipv4 := netip.MustParseAddr("100.64.0.1")

	node := (&types.Node{
		ID:        1,
		Hostname:  "node1",
		GivenName: "node1",
		IPv4:      &ipv4,
		Hostinfo:  &tailcfg.Hostinfo{OS: "linux"},
	}).View()

	mkCfg := func(enabled bool) *types.Config {
		cfg := &types.Config{
			BaseDomain: baseDomain,
			TailcfgDNSConfig: &tailcfg.DNSConfig{
				Domains: []string{baseDomain},
				Proxied: true,
			},
		}
		cfg.DNSConfig.HTTPSCerts.Enabled = enabled

		return cfg
	}

	t.Run("enabled_sets_node_fqdn", func(t *testing.T) {
		t.Parallel()

		got := generateDNSConfig(mkCfg(true), node, nil)

		want := []string{"node1.tailnet.example.com"}
		if diff := cmp.Diff(want, got.CertDomains); diff != "" {
			t.Errorf("CertDomains mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("disabled_leaves_certdomains_empty", func(t *testing.T) {
		t.Parallel()

		got := generateDNSConfig(mkCfg(false), node, nil)

		if len(got.CertDomains) != 0 {
			t.Errorf("CertDomains = %v, want empty when https_certs disabled", got.CertDomains)
		}
	})

	t.Run("node_without_given_name_gets_no_certdomains", func(t *testing.T) {
		t.Parallel()

		unnamed := (&types.Node{
			ID:       2,
			Hostname: "node2",
			IPv4:     &ipv4,
			Hostinfo: &tailcfg.Hostinfo{OS: "linux"},
		}).View()

		got := generateDNSConfig(mkCfg(true), unnamed, nil)

		if len(got.CertDomains) != 0 {
			t.Errorf("CertDomains = %v, want empty for a node without a valid FQDN", got.CertDomains)
		}
	})
}
