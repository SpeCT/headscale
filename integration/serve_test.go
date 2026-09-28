package integration

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/filter"
)

// TestServeHTTPSCertDomains verifies the control-plane side of per-node
// HTTPS certificates (dns.https_certs): headscale advertises each node's own
// FQDN in DNSConfig.CertDomains, grants the `https` node capability, and the
// `tailscale serve` CLI accepts an HTTPS listener configuration. Without the
// capability the CLI refuses with "error enabling https feature".
//
// The full certificate issuance flow (ACME DNS-01 against Let's Encrypt) is
// intentionally not exercised here: it requires base_domain to be a real,
// publicly delegated zone reachable by Let's Encrypt, which is not available
// in CI. The embedded authoritative DNS server and the /machine/set-dns
// handler are covered by unit tests in hscontrol/dns and hscontrol.
func TestServeHTTPSCertDomains(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1"},
		// Pin a released client: the serve CLI's HTTPS gating is what this
		// test exercises, and 1.102 is the version deployed alongside this
		// feature. "head" would build tailscale from source.
		Versions: []string{"1.102.4"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{
			// Userspace networking mirrors how the target deployment runs
			// tailscaled (no TUN device); serve and cert do not depend on
			// the data plane, so this also keeps the test runnable on
			// hosts without /dev/net/tun.
			tsic.WithDockerEntrypoint([]string{
				"/bin/sh", "-c",
				"while ! ip route show default >/dev/null 2>&1; do sleep 0.1; done ; " +
					// The harness writes headscale's CA after the container starts.
					"while [ ! -f /usr/local/share/ca-certificates/user-0.crt ]; do sleep 0.1; done ; " +
					"update-ca-certificates ; " +
					"tailscaled --tun=userspace-networking --verbose=10",
			}),
		},
		hsic.WithTestName("servecerts"),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_DNS_HTTPS_CERTS_ENABLED": "true",
			// A non-privileged port avoids clashing with anything the
			// container might bind on :53; delegation is irrelevant here
			// since we only assert the advertised control-plane state.
			"HEADSCALE_DNS_HTTPS_CERTS_LISTEN_ADDR": ":15353",
		}),
	)
	require.NoError(t, err)

	allClients, err := scenario.ListTailscaleClients()
	require.NoError(t, err)
	require.Len(t, allClients, 1)

	client := allClients[0]

	var fqdn string

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nm, err := client.Netmap()
		assert.NoError(c, err)

		if nm == nil || !nm.SelfNode.Valid() {
			assert.Fail(c, "client has no valid self node in netmap yet")

			return
		}

		// CertDomains are FQDNs without a trailing dot; the node's own
		// MagicDNS name must be the only entry.
		fqdn = strings.TrimSuffix(nm.SelfNode.Name(), ".")
		assert.Equal(c, []string{fqdn}, nm.DNS.CertDomains,
			"client netmap should advertise its own FQDN in DNSConfig.CertDomains")
		assert.True(c, nm.SelfNode.HasCap(tailcfg.CapabilityHTTPS),
			"self node should carry the https capability the serve CLI checks")
	}, 60*time.Second, 2*time.Second, "CertDomains and https capability should be advertised to the client")

	// Blocking: configure an HTTPS serve listener. This only succeeds when
	// the CLI sees the https capability; the certificate itself is fetched
	// lazily on the first connection and is not needed to set the config.
	stdout, stderr, err := client.Execute([]string{
		"tailscale", "serve", "--bg", "--https=443", "http://127.0.0.1:8080",
	})
	require.NoErrorf(t, err, "tailscale serve should accept an HTTPS listener: stdout=%s stderr=%s", stdout, stderr)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status, _, err := client.Execute([]string{"tailscale", "serve", "status"})
		assert.NoError(c, err)
		assert.Contains(c, status, "https://"+fqdn,
			"serve status should list the HTTPS listener on the node FQDN")
		assert.Contains(c, status, "http://127.0.0.1:8080",
			"serve status should list the proxied target")
	}, 30*time.Second, 2*time.Second, "serve status should reflect the HTTPS listener")
}

// TestFunnelNodeAttr verifies the control-plane side of Tailscale Funnel: a
// node granted the `funnel` attribute in the policy receives
// [tailcfg.NodeAttrFunnel] together with the allowed-ports capability the
// CLI parses ([policyv2.FunnelPortsCapability]), and a stock client accepts
// `tailscale funnel --bg --https=443 <target>` and reports the public URL. A node
// without the attribute is refused by the CLI.
//
// The public side (the ingress relay that dispatches TLS connections to
// the node's peer API) is a separate program and is not exercised here.
func TestFunnelNodeAttr(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	// Two users, no pre-created nodes: the funnel node is tagged so the
	// nodeAttrs target resolves at policy load, before any user exists.
	spec := ScenarioSpec{
		Users: []string{"funnel", "plain"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	pol := &policyv2.Policy{
		TagOwners: policyv2.TagOwners{
			policyv2.Tag("tag:funnel"):  policyv2.Owners{usernameOwner("funnel@")},
			policyv2.Tag("tag:ingress"): policyv2.Owners{usernameOwner("funnel@")},
		},
		ACLs: []policyv2.ACL{
			{
				Action:  "accept",
				Sources: []policyv2.Alias{wildcard()},
				Destinations: []policyv2.AliasWithPorts{
					aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
				},
			},
		},
		// Only tag:funnel nodes may use Funnel; the plain node is the
		// negative case.
		NodeAttrs: []policyv2.NodeAttrGrant{
			{
				Targets: policyv2.Aliases{tagp("tag:funnel")},
				Attrs:   []tailcfg.NodeCapability{tailcfg.NodeAttrFunnel},
			},
		},
		// The ingress relay may hand public connections to funnel nodes:
		// tailscaled accepts POST /v0/ingress only from a peer holding
		// https://tailscale.com/cap/ingress toward it. The policy spells it
		// without the scheme like every other app capability.
		Grants: []policyv2.Grant{
			{
				Sources:      policyv2.Aliases{tagp("tag:ingress")},
				Destinations: policyv2.Aliases{tagp("tag:funnel")},
				InternetProtocols: []policyv2.ProtocolPort{
					{Protocol: "*", Ports: []tailcfg.PortRange{tailcfg.PortRangeAny}},
				},
				App: tailcfg.PeerCapMap{
					policyv2.PeerCapabilityIngressGrant: {tailcfg.RawMessage("{}")},
				},
			},
		},
	}

	headscale, err := scenario.Headscale(
		hsic.WithTestName("funnelattr"),
		hsic.WithACLPolicy(pol),
		hsic.WithConfigEnv(map[string]string{
			// Funnel needs the https capability too; it comes with
			// dns.https_certs, as for HTTPS serve.
			"HEADSCALE_DNS_HTTPS_CERTS_ENABLED":     "true",
			"HEADSCALE_DNS_HTTPS_CERTS_LISTEN_ADDR": ":15353",
		}),
	)
	requireNoErrGetHeadscale(t, err)

	for _, user := range spec.Users {
		_, err = scenario.CreateUser(user)
		require.NoError(t, err)
	}

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	// Pin a released client: the funnel CLI's capability gating is what
	// this test exercises, and 1.102 is the version deployed alongside
	// this feature. Userspace networking mirrors how the target
	// deployment runs tailscaled (no TUN device); funnel configuration
	// does not depend on the data plane.
	const clientVersion = "1.102.4"

	networks := scenario.Networks()
	require.Len(t, networks, 1, "scenario should have exactly the default network")

	defaultNetwork := tsic.WithNetwork(networks[0])

	userspaceEntrypoint := tsic.WithDockerEntrypoint([]string{
		"/bin/sh", "-c",
		"while ! ip route show default >/dev/null 2>&1; do sleep 0.1; done ; " +
			"while [ ! -f /usr/local/share/ca-certificates/user-0.crt ]; do sleep 0.1; done ; " +
			"update-ca-certificates ; " +
			"tailscaled --tun=userspace-networking --verbose=10",
	})

	funnelClient, err := scenario.CreateTailscaleNode(clientVersion, defaultNetwork, userspaceEntrypoint)
	require.NoError(t, err)

	defer func() { _, _, _ = funnelClient.Shutdown() }()

	pakFunnel, err := scenario.CreatePreAuthKeyWithTags(userMap["funnel"].GetId(), false, false, []string{"tag:funnel"})
	require.NoError(t, err)
	require.NoError(t, funnelClient.Login(headscale.GetEndpoint(), pakFunnel.GetKey()))
	require.NoError(t, funnelClient.WaitForRunning(30*time.Second))

	plainClient, err := scenario.CreateTailscaleNode(clientVersion, defaultNetwork, userspaceEntrypoint)
	require.NoError(t, err)

	defer func() { _, _, _ = plainClient.Shutdown() }()

	pakPlain, err := scenario.CreatePreAuthKeyWithTags(userMap["plain"].GetId(), false, false, nil)
	require.NoError(t, err)
	require.NoError(t, plainClient.Login(headscale.GetEndpoint(), pakPlain.GetKey()))
	require.NoError(t, plainClient.WaitForRunning(30*time.Second))

	// The relay stands in for the ingress program; only its identity
	// (tag:ingress) matters here.
	ingressClient, err := scenario.CreateTailscaleNode(clientVersion, defaultNetwork, userspaceEntrypoint)
	require.NoError(t, err)

	defer func() { _, _, _ = ingressClient.Shutdown() }()

	pakIngress, err := scenario.CreatePreAuthKeyWithTags(userMap["funnel"].GetId(), false, false, []string{"tag:ingress"})
	require.NoError(t, err)
	require.NoError(t, ingressClient.Login(headscale.GetEndpoint(), pakIngress.GetKey()))
	require.NoError(t, ingressClient.WaitForRunning(30*time.Second))

	ingressIP, err := ingressClient.IPv4()
	require.NoError(t, err)

	funnelIP, err := funnelClient.IPv4()
	require.NoError(t, err)

	var fqdn string

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nm, err := funnelClient.Netmap()
		assert.NoError(c, err)

		if nm == nil || !nm.SelfNode.Valid() {
			assert.Fail(c, "client has no valid self node in netmap yet")

			return
		}

		fqdn = strings.TrimSuffix(nm.SelfNode.Name(), ".")
		assert.True(c, nm.SelfNode.HasCap(tailcfg.CapabilityHTTPS), "self node should carry https")
		assert.True(c, nm.SelfNode.HasCap(tailcfg.NodeAttrFunnel), "self node should carry funnel")
		assert.True(c, nm.SelfNode.HasCap(policyv2.FunnelPortsCapability),
			"self node should carry the funnel-ports capability with the allowed ports")

		// The relay's grant arrives as the URL-form peer capability
		// tailscaled's canIngress checks, directed at this node from the
		// relay's address.
		assert.True(c, hasCapMatchFromTo(nm.PacketFilter, tailcfg.PeerCapabilityIngress, ingressIP, funnelIP),
			"funnel node's packet filter should grant %s from the ingress node %s to itself %s", tailcfg.PeerCapabilityIngress, ingressIP, funnelIP)
	}, 60*time.Second, 2*time.Second, "funnel capabilities should be advertised to the tagged client")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nm, err := plainClient.Netmap()
		assert.NoError(c, err)

		if nm == nil || !nm.SelfNode.Valid() {
			assert.Fail(c, "client has no valid self node in netmap yet")

			return
		}

		assert.True(c, nm.SelfNode.HasCap(tailcfg.CapabilityHTTPS), "self node should carry https")
		assert.False(c, nm.SelfNode.HasCap(tailcfg.NodeAttrFunnel), "the plain node must not carry funnel")
		assert.False(c, nm.SelfNode.HasCap(policyv2.FunnelPortsCapability), "the plain node must not carry funnel-ports")
		assert.False(c, hasCapMatchInPacketFilter(nm.PacketFilter, tailcfg.PeerCapabilityIngress),
			"the plain node is not a grant destination and must not accept ingress")
	}, 60*time.Second, 2*time.Second, "the plain client should not receive funnel capabilities")

	// Blocking: enable Funnel on 443. The CLI checks the three capabilities
	// locally and would otherwise fail with "Funnel not available".
	stdout, stderr, err := funnelClient.Execute([]string{
		"tailscale", "funnel", "--bg", "--https=443", "http://127.0.0.1:8080",
	})
	require.NoErrorf(t, err, "tailscale funnel should be accepted: stdout=%s stderr=%s", stdout, stderr)

	// The negative case: no funnel attribute, so the CLI refuses.
	stdout, stderr, err = plainClient.Execute([]string{
		"tailscale", "funnel", "--bg", "--https=443", "http://127.0.0.1:8080",
	})
	require.Errorf(t, err, "tailscale funnel must be refused without the funnel attribute: stdout=%s stderr=%s", stdout, stderr)
	assert.Contains(t, stdout+stderr, "Funnel not available")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status, _, err := funnelClient.Execute([]string{"tailscale", "funnel", "status"})
		assert.NoError(c, err)
		assert.Contains(c, status, "https://"+fqdn,
			"funnel status should list the public URL on the node FQDN")
		assert.Contains(c, status, "Funnel on",
			"funnel status should report the listener as public")
		assert.Contains(c, status, "http://127.0.0.1:8080",
			"funnel status should list the proxied target")
	}, 30*time.Second, 2*time.Second, "funnel status should reflect the public listener")
}

// hasCapMatchFromTo reports whether the packet filter carries peerCap from
// src to dst: a [filter.Match] whose Srcs contain src with a [filter.CapMatch]
// for peerCap whose Dst contains dst.
func hasCapMatchFromTo(pf []filter.Match, peerCap tailcfg.PeerCapability, src, dst netip.Addr) bool {
	for _, m := range pf {
		if !slices.ContainsFunc(m.Srcs, func(p netip.Prefix) bool { return p.Contains(src) }) {
			continue
		}

		for _, cm := range m.Caps {
			if cm.Cap == peerCap && cm.Dst.Contains(dst) {
				return true
			}
		}
	}

	return false
}
