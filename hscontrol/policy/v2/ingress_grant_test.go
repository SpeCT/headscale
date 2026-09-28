package v2

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestIngressGrant verifies the self-hosted Funnel relay permission: a grant
// with app "tailscale.com/cap/ingress" from the relay tag reaches the
// destination nodes' packet filter as the URL-form capability tailscaled
// checks before accepting POST /v0/ingress, while the URL form itself is
// rejected in the policy like every other scheme-prefixed name.
func TestIngressGrant(t *testing.T) {
	t.Parallel()

	users := nodeAttrsTestUsers()
	nodes := nodeAttrsTestNodes(users)

	policy := `{
		"tagOwners": {` + nodeAttrsTagOwners + `,
			"tag:ingress": ["alice@example.com"]},
		"nodeAttrs": [{"target": ["alice@example.com"], "attr": ["funnel"]}],
		"grants": [
			{"src": ["*"], "dst": ["*"], "ip": ["*"]},
			{"src": ["tag:ingress"], "dst": ["autogroup:member"], "ip": ["*"],
			 "app": {"tailscale.com/cap/ingress": [{}]}}
		]
	}`

	relay := nodes[2] // tag:server in the fixture; retag it as the relay
	relay.Tags = []string{"tag:ingress"}

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	// alice-laptop (user-owned) must see the ingress cap granted from the
	// relay's address, in the wire form.
	rules, err := pm.FilterForNode(nodes[0].View())
	require.NoError(t, err)

	var found bool

	for _, rule := range rules {
		for _, cg := range rule.CapGrant {
			_, bare := cg.CapMap[PeerCapabilityIngressGrant]
			assert.False(t, bare, "the {domain}/{path} spelling must not reach the client")

			if _, ok := cg.CapMap[tailcfg.PeerCapabilityIngress]; ok {
				found = true

				assert.Contains(t, rule.SrcIPs, "100.64.0.3", "cap must be granted from the relay only")

				for _, d := range cg.Dsts {
					assert.False(t, d.Contains(netip.MustParseAddr("100.64.0.4")), "tagged nodes are not autogroup:member")
				}
			}
		}
	}

	assert.True(t, found, "alice-laptop should have the ingress cap from the relay: %+v", rules)

	// A tagged node is not autogroup:member and gets no ingress cap.
	rules, err = pm.FilterForNode(nodes[3].View())
	require.NoError(t, err)

	for _, rule := range rules {
		for _, cg := range rule.CapGrant {
			_, ok := cg.CapMap[tailcfg.PeerCapabilityIngress]
			assert.False(t, ok, "tag:client must not receive the ingress cap")
		}
	}

	// The policy itself keeps the operator's spelling.
	require.Len(t, pm.pol.Grants, 2)
	_, ok := pm.pol.Grants[1].App[PeerCapabilityIngressGrant]
	assert.True(t, ok, "canonicalisation must not mutate the parsed policy")
}

func TestIngressGrantRejectsURLForm(t *testing.T) {
	t.Parallel()

	users := nodeAttrsTestUsers()
	nodes := nodeAttrsTestNodes(users)

	for _, tt := range []struct {
		name    string
		app     string
		wantErr error
	}{
		{"url form rejected", `"https://tailscale.com/cap/ingress"`, ErrCapNameInvalidForm},
		{"funnel stays server-only", `"tailscale.com/cap/funnel"`, ErrCapNameTailscaleDomain},
		{"bare ingress accepted", `"tailscale.com/cap/ingress"`, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			policy := `{
				"tagOwners": {` + nodeAttrsTagOwners + `},
				"grants": [{"src": ["tag:server"], "dst": ["autogroup:member"], "app": {` + tt.app + `: [{}]}}]
			}`

			_, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
			if tt.wantErr == nil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}
