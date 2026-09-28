package dns

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureResponseWriter is a minimal [dns.ResponseWriter] that records the
// message written by the handler so tests can assert on it without binding
// a real listener.
type captureResponseWriter struct {
	msg    *dns.Msg
	remote net.Addr
}

func (w *captureResponseWriter) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (w *captureResponseWriter) RemoteAddr() net.Addr        { return w.remote }
func (w *captureResponseWriter) WriteMsg(m *dns.Msg) error   { w.msg = m; return nil }
func (w *captureResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *captureResponseWriter) Close() error                { return nil }
func (w *captureResponseWriter) TsigStatus() error           { return nil }
func (w *captureResponseWriter) TsigTimersOnly(bool)         {}
func (w *captureResponseWriter) Hijack()                     {}

func query(t *testing.T, s *ACMEChallengeServer, name string, qtype uint16) *dns.Msg {
	t.Helper()

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)

	w := &captureResponseWriter{remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}}
	s.serveDNS(w, req)

	require.NotNil(t, w.msg, "handler wrote no response for %s/%d", name, qtype)

	return w.msg
}

func newTestServer() *ACMEChallengeServer {
	return NewACMEChallengeServer("tailnet.example.com", "ns1.example.com", "127.0.0.1:0")
}

func TestValidACMEChallengeValue(t *testing.T) {
	t.Parallel()

	assert.True(t, ValidACMEChallengeValue("gfj9Xq-1234_ABC"))
	assert.True(t, ValidACMEChallengeValue(strings.Repeat("a", MaxACMEChallengeValueLength)))
	assert.False(t, ValidACMEChallengeValue(""))
	assert.False(t, ValidACMEChallengeValue(strings.Repeat("a", MaxACMEChallengeValueLength+1)))
	assert.False(t, ValidACMEChallengeValue("has space"))
	assert.False(t, ValidACMEChallengeValue("tab\there"))
	assert.False(t, ValidACMEChallengeValue("newline\n"))
	assert.False(t, ValidACMEChallengeValue("non-ascii-é"))
}

func TestACMEChallengeServerTXT(t *testing.T) {
	t.Parallel()

	s := newTestServer()
	require.NoError(t, s.SetTXT("_acme-challenge.host.tailnet.example.com", "token-value"))

	m := query(t, s, "_acme-challenge.host.tailnet.example.com", dns.TypeTXT)

	assert.Equal(t, dns.RcodeSuccess, m.Rcode)
	assert.True(t, m.Authoritative)
	assert.False(t, m.RecursionAvailable)
	require.Len(t, m.Answer, 1)

	txt, ok := m.Answer[0].(*dns.TXT)
	require.True(t, ok, "answer is %T, want *dns.TXT", m.Answer[0])
	assert.Equal(t, []string{"token-value"}, txt.Txt)
	assert.Equal(t, uint32(acmeAnswerTTL), txt.Hdr.Ttl)
}

func TestACMEChallengeServerSetTXTRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	s := newTestServer()
	name := "_acme-challenge.host.tailnet.example.com"

	require.ErrorIs(t, s.SetTXT(name, ""), ErrInvalidACMEChallengeValue)
	require.ErrorIs(t, s.SetTXT(name, strings.Repeat("x", 256)), ErrInvalidACMEChallengeValue)
	require.ErrorIs(t, s.SetTXT(name, "a b"), ErrInvalidACMEChallengeValue)
	assert.Empty(t, s.TXT(name))
}

func TestACMEChallengeServerMultipleValues(t *testing.T) {
	t.Parallel()

	s := newTestServer()
	name := "_acme-challenge.host.tailnet.example.com"
	require.NoError(t, s.SetTXT(name, "value-1"))
	require.NoError(t, s.SetTXT(name, "value-2"))
	// Setting an existing value again must not create a duplicate RR.
	require.NoError(t, s.SetTXT(name, "value-1"))

	m := query(t, s, name, dns.TypeTXT)
	require.Len(t, m.Answer, 2, "one RR per distinct value")

	for _, rr := range m.Answer {
		txt, ok := rr.(*dns.TXT)
		require.True(t, ok)
		assert.Len(t, txt.Txt, 1, "each value must be its own character-string")
	}
}

func TestACMEChallengeServerCapsValuesPerName(t *testing.T) {
	t.Parallel()

	s := newTestServer()
	name := "_acme-challenge.host.tailnet.example.com"

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tick := 0
	s.now = func() time.Time {
		tick++

		return base.Add(time.Duration(tick) * time.Second)
	}

	for i := range maxTXTValuesPerName + 3 {
		require.NoError(t, s.SetTXT(name, "value-"+string(rune('a'+i))))
	}

	got := s.TXT(name)
	assert.Len(t, got, maxTXTValuesPerName)
	// The oldest values were replaced; the newest survive.
	assert.NotContains(t, got, "value-a")
	assert.Contains(t, got, "value-"+string(rune('a'+maxTXTValuesPerName+2)))
}

func TestACMEChallengeServerCaseInsensitive(t *testing.T) {
	t.Parallel()

	s := newTestServer()
	require.NoError(t, s.SetTXT("_acme-challenge.HOST.Tailnet.Example.com", "token"))

	m := query(t, s, "_acme-challenge.host.tailnet.example.COM", dns.TypeTXT)
	assert.Len(t, m.Answer, 1, "lookup must be case-insensitive")
}

func TestACMEChallengeServerNODATA(t *testing.T) {
	t.Parallel()

	s := newTestServer()
	require.NoError(t, s.SetTXT("_acme-challenge.host.tailnet.example.com", "token"))

	tests := []struct {
		name  string
		qname string
		qtype uint16
	}{
		{"txt-unknown-name", "other.tailnet.example.com", dns.TypeTXT},
		{"a-for-node", "host.tailnet.example.com", dns.TypeA},
		{"aaaa-for-node", "host.tailnet.example.com", dns.TypeAAAA},
		{"a-for-challenge-name", "_acme-challenge.host.tailnet.example.com", dns.TypeA},
		{"caa-for-node", "host.tailnet.example.com", dns.TypeCAA},
		{"caa-for-apex", "tailnet.example.com", dns.TypeCAA},
		{"a-for-apex", "tailnet.example.com", dns.TypeA},
		{"ns-for-subname", "host.tailnet.example.com", dns.TypeNS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := query(t, s, tt.qname, tt.qtype)

			assert.Equal(t, dns.RcodeSuccess, m.Rcode, "NODATA must be NOERROR")
			assert.True(t, m.Authoritative)
			assert.Empty(t, m.Answer, "no address or other data may leak")
			require.Len(t, m.Ns, 1)
			_, ok := m.Ns[0].(*dns.SOA)
			assert.True(t, ok, "authority record is %T, want *dns.SOA", m.Ns[0])
		})
	}
}

func TestACMEChallengeServerSOAandNS(t *testing.T) {
	t.Parallel()

	s := newTestServer()

	soa := query(t, s, "tailnet.example.com", dns.TypeSOA)
	require.Len(t, soa.Answer, 1)
	soaRR, ok := soa.Answer[0].(*dns.SOA)
	require.True(t, ok)
	assert.Equal(t, "ns1.example.com.", soaRR.Ns)
	assert.Equal(t, "hostmaster.tailnet.example.com.", soaRR.Mbox)

	ns := query(t, s, "tailnet.example.com", dns.TypeNS)
	require.Len(t, ns.Answer, 1)
	nsRR, ok := ns.Answer[0].(*dns.NS)
	require.True(t, ok)
	assert.Equal(t, "ns1.example.com.", nsRR.Ns)
}

func TestACMEChallengeServerOutOfZoneRefused(t *testing.T) {
	t.Parallel()

	s := newTestServer()
	require.NoError(t, s.SetTXT("_acme-challenge.host.tailnet.example.com", "token"))

	for _, qname := range []string{
		"_acme-challenge.host.other.example.org",
		"example.com",
		"tailnet.example.com.evil.example",
		"nottailnet.example.com",
	} {
		m := query(t, s, qname, dns.TypeTXT)
		assert.Equal(t, dns.RcodeRefused, m.Rcode, "out-of-zone %s must be REFUSED", qname)
		assert.False(t, m.Authoritative)
		assert.Empty(t, m.Answer)
	}
}

func TestACMEChallengeServerRejectsMalformedQueries(t *testing.T) {
	t.Parallel()

	s := newTestServer()

	req := new(dns.Msg)
	req.SetQuestion("tailnet.example.com.", dns.TypeSOA)
	req.Opcode = dns.OpcodeUpdate

	w := &captureResponseWriter{remote: &net.UDPAddr{}}
	s.serveDNS(w, req)
	require.NotNil(t, w.msg)
	assert.Equal(t, dns.RcodeNotImplemented, w.msg.Rcode, "dynamic update must not be accepted")

	req = new(dns.Msg)
	req.SetQuestion("tailnet.example.com.", dns.TypeSOA)
	req.Question = append(req.Question, dns.Question{Name: "x.tailnet.example.com.", Qtype: dns.TypeTXT, Qclass: dns.ClassINET})

	w = &captureResponseWriter{remote: &net.UDPAddr{}}
	s.serveDNS(w, req)
	require.NotNil(t, w.msg)
	assert.Equal(t, dns.RcodeFormatError, w.msg.Rcode)
}

func TestACMEChallengeServerEDNS(t *testing.T) {
	t.Parallel()

	s := newTestServer()

	req := new(dns.Msg)
	req.SetQuestion("tailnet.example.com.", dns.TypeSOA)
	req.SetEdns0(4096, true)

	w := &captureResponseWriter{remote: &net.UDPAddr{}}
	s.serveDNS(w, req)
	require.NotNil(t, w.msg)

	opt := w.msg.IsEdns0()
	require.NotNil(t, opt, "EDNS0 must be echoed when the client offered it")
	assert.Equal(t, uint16(udpMaxSize), opt.UDPSize())
}

func TestACMEChallengeServerExpiry(t *testing.T) {
	t.Parallel()

	s := newTestServer()
	name := "_acme-challenge.host.tailnet.example.com"

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base
	s.now = func() time.Time { return now }

	require.NoError(t, s.SetTXT(name, "stale"))

	now = base.Add(acmeRecordTTL - time.Minute)

	require.NoError(t, s.SetTXT(name, "live"))

	// Just past the first value's lifetime: it is hidden but not yet evicted.
	now = base.Add(acmeRecordTTL + time.Second)

	assert.Equal(t, []string{"live"}, s.TXT(name))
	assert.Len(t, s.records[dns.CanonicalName(name)], 2)

	s.evictExpired()
	assert.Len(t, s.records[dns.CanonicalName(name)], 1)

	// Once everything has expired the name disappears entirely.
	now = base.Add(2*acmeRecordTTL + time.Second)

	assert.Empty(t, s.TXT(name))
	s.evictExpired()

	_, present := s.records[dns.CanonicalName(name)]
	assert.False(t, present, "fully expired names must be removed")
}

// TestACMEChallengeServerListeners binds real UDP and TCP sockets on a
// random loopback port and resolves through them with a DNS client.
func TestACMEChallengeServerListeners(t *testing.T) {
	t.Parallel()

	s := newTestServer()
	require.NoError(t, s.Start())
	t.Cleanup(func() { _ = s.Close() })

	require.NoError(t, s.SetTXT("_acme-challenge.host.tailnet.example.com", "listener-token"))

	for _, net := range []string{"udp", "tcp"} {
		t.Run(net, func(t *testing.T) {
			t.Parallel()

			addr := s.UDPAddr().String()
			if net == "tcp" {
				addr = s.TCPAddr().String()
			}

			c := &dns.Client{Net: net, Timeout: 5 * time.Second}

			req := new(dns.Msg)
			req.SetQuestion("_acme-challenge.host.tailnet.example.com.", dns.TypeTXT)
			req.SetEdns0(1232, false)

			resp, _, err := c.Exchange(req, addr)
			require.NoError(t, err)
			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
			assert.True(t, resp.Authoritative)
			require.Len(t, resp.Answer, 1)
			txt, ok := resp.Answer[0].(*dns.TXT)
			require.True(t, ok)
			assert.Equal(t, []string{"listener-token"}, txt.Txt)

			req = new(dns.Msg)
			req.SetQuestion("host.tailnet.example.com.", dns.TypeA)
			resp, _, err = c.Exchange(req, addr)
			require.NoError(t, err)
			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
			assert.Empty(t, resp.Answer, "A record for a node must not be served publicly")
		})
	}
}

func TestACMEChallengeServerCloseIdempotent(t *testing.T) {
	t.Parallel()

	s := newTestServer()
	require.NoError(t, s.Close(), "Close before Start must be safe")
	require.NoError(t, s.Close())

	s = newTestServer()
	require.NoError(t, s.Start())
	require.NoError(t, s.Close())
	require.NoError(t, s.Close())
}

func TestACMEChallengeServerStartBindError(t *testing.T) {
	t.Parallel()

	first := newTestServer()
	require.NoError(t, first.Start())
	t.Cleanup(func() { _ = first.Close() })

	// Reusing the bound UDP port must surface a bind error rather than a
	// silently dead listener.
	second := NewACMEChallengeServer("tailnet.example.com", "ns1.example.com", first.UDPAddr().String())
	err := second.Start()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "binding")

	_ = second.Close()
}
