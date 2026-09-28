package integration

import (
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
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
