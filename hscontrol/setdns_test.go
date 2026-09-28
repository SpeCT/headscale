package hscontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	hsdns "github.com/juanfont/headscale/hscontrol/dns"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const setDNSTestBaseDomain = "tailnet.example.com"

// putNamedTestNodeInStore registers a node like putTestNodeInStore but also
// assigns its MagicDNS given name, which real registration does and which
// the set-dns handler needs to derive the node FQDN.
func putNamedTestNodeInStore(t *testing.T, app *Headscale, user *types.User, hostname string) *types.Node {
	t.Helper()

	node := app.state.CreateNodeForTest(user, hostname)
	node.GivenName = hostname
	app.state.PutNodeInStoreForTest(*node)

	return node
}

// setDNSTestEnv is a headscale app with per-node HTTPS certificates enabled,
// an in-memory ACME challenge server (never bound to a socket) and one
// registered node whose machine key the noise session carries.
type setDNSTestEnv struct {
	app  *Headscale
	node *types.Node
	ns   *noiseServer
}

func newSetDNSTestEnv(t *testing.T) *setDNSTestEnv {
	t.Helper()

	app := createTestApp(t)
	app.cfg.BaseDomain = setDNSTestBaseDomain
	app.cfg.DNSConfig.MagicDNS = true
	app.cfg.DNSConfig.BaseDomain = setDNSTestBaseDomain
	app.cfg.DNSConfig.HTTPSCerts.Enabled = true
	app.acmeDNS = hsdns.NewACMEChallengeServer(setDNSTestBaseDomain, "ns1.example.com", "127.0.0.1:0")

	user := app.state.CreateUserForTest("set-dns-user")
	node := putNamedTestNodeInStore(t, app, user, "node-a")

	return &setDNSTestEnv{
		app:  app,
		node: node,
		ns: &noiseServer{
			headscale:  app,
			machineKey: node.MachineKey,
		},
	}
}

func (e *setDNSTestEnv) challengeName(t *testing.T, node *types.Node) string {
	t.Helper()

	fqdn, err := node.GetFQDN(setDNSTestBaseDomain)
	require.NoError(t, err)

	return hsdns.ACMEChallengePrefix + strings.TrimSuffix(fqdn, ".")
}

func (e *setDNSTestEnv) request(t *testing.T, req tailcfg.SetDNSRequest) *httptest.ResponseRecorder {
	t.Helper()

	body, err := json.Marshal(req)
	require.NoError(t, err)

	return e.rawRequest(t, body)
}

func (e *setDNSTestEnv) rawRequest(t *testing.T, body []byte) *httptest.ResponseRecorder {
	t.Helper()

	httpReq := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/machine/set-dns", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	e.ns.SetDNSHandler(rec, httpReq)

	return rec
}

func (e *setDNSTestEnv) validRequest(t *testing.T) tailcfg.SetDNSRequest {
	t.Helper()

	return tailcfg.SetDNSRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: e.node.NodeKey,
		Name:    e.challengeName(t, e.node),
		Type:    "TXT",
		Value:   "gfj9Xq-Pf5J0TWzQIRfr2p4OO8MIOn5LfwF1Uv8_5PA",
	}
}

func TestSetDNSHandler_PublishesOwnChallenge(t *testing.T) {
	t.Parallel()

	env := newSetDNSTestEnv(t)
	req := env.validRequest(t)

	rec := env.request(t, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))

	var resp tailcfg.SetDNSResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	assert.Equal(t, []string{req.Value}, env.app.acmeDNS.TXT(req.Name),
		"the challenge must be served by the ACME DNS server")
}

func TestSetDNSHandler_NameMatchingIsCaseAndDotInsensitive(t *testing.T) {
	t.Parallel()

	env := newSetDNSTestEnv(t)
	req := env.validRequest(t)
	req.Name = strings.ToUpper(req.Name) + "."

	rec := env.request(t, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []string{req.Value}, env.app.acmeDNS.TXT(env.challengeName(t, env.node)))
}

func TestSetDNSHandler_RepeatedAndConcurrentValuesCoexist(t *testing.T) {
	t.Parallel()

	env := newSetDNSTestEnv(t)
	req := env.validRequest(t)

	first := env.request(t, req)
	require.Equal(t, http.StatusOK, first.Code)

	// A retry of the same challenge is idempotent.
	again := env.request(t, req)
	require.Equal(t, http.StatusOK, again.Code)

	// A second, concurrent renewal for the same name must not clobber the
	// first challenge value.
	second := req
	second.Value = "second-order-ZmFrZS1jaGFsbGVuZ2UtdmFsdWU"
	rec := env.request(t, second)
	require.Equal(t, http.StatusOK, rec.Code)

	assert.ElementsMatch(t, []string{req.Value, second.Value}, env.app.acmeDNS.TXT(req.Name))
}

func TestSetDNSHandler_NotEnabled(t *testing.T) {
	t.Parallel()

	env := newSetDNSTestEnv(t)
	env.app.acmeDNS = nil

	rec := env.request(t, env.validRequest(t))

	assert.Equal(t, http.StatusNotImplemented, rec.Code, rec.Body.String())
}

func TestSetDNSHandler_RejectsWrongMethod(t *testing.T) {
	t.Parallel()

	env := newSetDNSTestEnv(t)

	httpReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/machine/set-dns", nil)
	rec := httptest.NewRecorder()
	env.ns.SetDNSHandler(rec, httpReq)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestSetDNSHandler_RejectsMalformedBody(t *testing.T) {
	t.Parallel()

	env := newSetDNSTestEnv(t)

	rec := env.rawRequest(t, []byte("{not json"))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Bodies above the per-endpoint limit are rejected before validation.
	oversized := []byte(`{"Value":"` + strings.Repeat("a", int(setDNSBodyLimit)) + `"}`)
	rec = env.rawRequest(t, oversized)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	assert.Empty(t, env.app.acmeDNS.TXT(env.challengeName(t, env.node)))
}

func TestSetDNSHandler_RejectsUnknownNode(t *testing.T) {
	t.Parallel()

	env := newSetDNSTestEnv(t)
	req := env.validRequest(t)
	req.NodeKey = key.NewNode().Public()

	rec := env.request(t, req)

	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	assert.Empty(t, env.app.acmeDNS.TXT(req.Name))
}

func TestSetDNSHandler_RejectsMachineKeyMismatch(t *testing.T) {
	t.Parallel()

	env := newSetDNSTestEnv(t)
	// The noise session belongs to some other machine than the node key
	// named in the request.
	env.ns.machineKey = key.NewMachine().Public()

	rec := env.request(t, env.validRequest(t))

	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	assert.Empty(t, env.app.acmeDNS.TXT(env.challengeName(t, env.node)))
}

func TestSetDNSHandler_RejectsExpiredNode(t *testing.T) {
	t.Parallel()

	env := newSetDNSTestEnv(t)

	past := time.Now().Add(-time.Hour)
	env.node.Expiry = &past
	env.app.state.PutNodeInStoreForTest(*env.node)

	rec := env.request(t, env.validRequest(t))

	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Empty(t, env.app.acmeDNS.TXT(env.challengeName(t, env.node)))
}

func TestSetDNSHandler_RejectsNamesNotOwnedByNode(t *testing.T) {
	t.Parallel()

	env := newSetDNSTestEnv(t)

	user := env.app.state.CreateUserForTest("set-dns-other-user")
	sibling := putNamedTestNodeInStore(t, env.app, user, "node-b")

	own := env.challengeName(t, env.node)

	names := map[string]string{
		"sibling node":      env.challengeName(t, sibling),
		"zone apex":         hsdns.ACMEChallengePrefix + setDNSTestBaseDomain,
		"wildcard":          hsdns.ACMEChallengePrefix + "*." + setDNSTestBaseDomain,
		"bare fqdn":         strings.TrimPrefix(own, hsdns.ACMEChallengePrefix),
		"subdomain of own":  hsdns.ACMEChallengePrefix + "app." + strings.TrimPrefix(own, hsdns.ACMEChallengePrefix),
		"suffix match":      "evil-" + own,
		"other zone":        hsdns.ACMEChallengePrefix + "node-a.example.org",
		"control server":    hsdns.ACMEChallengePrefix + "headscale.example.com",
		"path-like":         own + "/../" + setDNSTestBaseDomain,
		"embedded nul":      own + "\x00",
		"leading dot":       "." + own,
		"empty":             "",
		"double prefix":     hsdns.ACMEChallengePrefix + own,
		"trailing garbage":  own + ".evil",
		"whitespace padded": " " + own,
	}

	for label, name := range names {
		t.Run(label, func(t *testing.T) {
			t.Parallel()

			req := env.validRequest(t)
			req.Name = name

			rec := env.request(t, req)

			assert.Equal(t, http.StatusForbidden, rec.Code, "name %q: %s", name, rec.Body.String())
		})
	}

	assert.Empty(t, env.app.acmeDNS.TXT(env.challengeName(t, sibling)))
	assert.Empty(t, env.app.acmeDNS.TXT(own))
}

func TestSetDNSHandler_RejectsNonTXT(t *testing.T) {
	t.Parallel()

	env := newSetDNSTestEnv(t)

	for _, typ := range []string{"A", "AAAA", "CNAME", "NS", "", "txt-ish"} {
		req := env.validRequest(t)
		req.Type = typ

		rec := env.request(t, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code, "type %q", typ)
	}

	// Type matching is case-insensitive, matching the client.
	req := env.validRequest(t)
	req.Type = "txt"
	rec := env.request(t, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestSetDNSHandler_RejectsInvalidValues(t *testing.T) {
	t.Parallel()

	env := newSetDNSTestEnv(t)

	for label, value := range map[string]string{
		"empty":     "",
		"too long":  strings.Repeat("a", hsdns.MaxACMEChallengeValueLength+1),
		"space":     "a b",
		"newline":   "a\nb",
		"control":   "a\x01b",
		"non-ascii": "ünïcode",
	} {
		req := env.validRequest(t)
		req.Value = value

		rec := env.request(t, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code, "value %s", label)
	}

	assert.Empty(t, env.app.acmeDNS.TXT(env.challengeName(t, env.node)))
}
