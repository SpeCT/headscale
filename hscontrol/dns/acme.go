package dns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

const (
	// ACMEChallengePrefix is the label ACME DNS-01 prepends to the name being
	// validated: the TXT record for "host.example.com" is published at
	// "_acme-challenge.host.example.com".
	ACMEChallengePrefix = "_acme-challenge."

	// MaxACMEChallengeValueLength is the longest challenge value accepted.
	// A single TXT character-string cannot exceed 255 bytes; a real DNS-01
	// value is 43 bytes of base64url.
	MaxACMEChallengeValueLength = 255

	// acmeRecordTTL is how long a challenge value stays published after it
	// was last set. Let's Encrypt validates DNS-01 challenges within seconds
	// to a few minutes, so a short lifetime keeps stale values from
	// lingering once a certificate has been issued. Records live only in
	// memory, so nothing survives a restart either.
	acmeRecordTTL = 10 * time.Minute

	// acmeAnswerTTL is the DNS TTL (seconds) of challenge answers. It is
	// tiny so resolvers never cache a value across renewals.
	acmeAnswerTTL = 1

	// acmeZoneTTL is the DNS TTL (seconds) of the apex SOA and NS answers.
	acmeZoneTTL = 300

	// ingressAnswerTTL is the DNS TTL (seconds) of the A/AAAA answers that
	// point node names at the Funnel ingress relay. Long enough to be
	// cache friendly, short enough that moving the relay propagates within
	// minutes.
	ingressAnswerTTL = 300

	// acmeCleanupInterval is how often expired values are evicted.
	acmeCleanupInterval = time.Minute

	// maxTXTValuesPerName bounds memory per name so a node cannot grow the
	// record set without limit by starting many challenges.
	maxTXTValuesPerName = 8

	// udpMinSize and udpMaxSize bound UDP responses: 512 bytes without EDNS
	// and at most 1232 bytes with EDNS, the widely deployed safe size.
	udpMinSize = dns.MinMsgSize
	udpMaxSize = 1232
)

var (
	// ErrInvalidACMEChallengeValue is returned when a challenge value cannot
	// be published as a single TXT character-string.
	ErrInvalidACMEChallengeValue = errors.New(
		"ACME challenge value must be 1-255 printable ASCII characters without spaces",
	)

	// ErrACMEListenerExited is returned by Start when a listener goroutine
	// exits before the server reports itself as serving.
	ErrACMEListenerExited = errors.New("ACME challenge DNS listener exited during startup")
)

// ValidACMEChallengeValue reports whether value can be published as a single
// TXT character-string: 1 to [MaxACMEChallengeValueLength] bytes of printable
// ASCII without spaces or control characters.
func ValidACMEChallengeValue(value string) bool {
	if value == "" || len(value) > MaxACMEChallengeValueLength {
		return false
	}

	for i := range len(value) {
		if value[i] <= ' ' || value[i] > '~' {
			return false
		}
	}

	return true
}

// ACMEChallengeServer is a minimal authoritative DNS server for the MagicDNS
// base domain. It answers the `_acme-challenge.<fqdn>` TXT lookups that
// Tailscale clients rely on to complete ACME DNS-01 challenges
// (`tailscale cert` and `tailscale serve --https`).
//
// Nodes publish challenge values through the `/machine/set-dns` Noise
// endpoint; this server returns them to public resolvers (Let's Encrypt)
// until they expire. Only the zone apex SOA/NS records and the published
// challenge TXT records are served. Node A/AAAA records are deliberately not
// served here: address resolution stays inside the tailnet via MagicDNS.
//
// The exception is Funnel: when ingressAddrs is set, every name below the
// apex resolves to those public addresses, as *.ts.net resolves to
// Tailscale's ingress relays. The relay dispatches on the TLS SNI, so the
// node's tailnet address still never appears in public DNS.
//
// For the challenges to validate, the base domain must be a real, publicly
// delegated zone whose NS record points at this server.
type ACMEChallengeServer struct {
	zone       string // base domain, canonical (lowercase, trailing dot)
	nameserver string // authoritative NS FQDN, canonical
	listenAddr string

	// ingressAddrs are the public addresses answered for A/AAAA queries of
	// any name below the apex. Empty means NODATA, as before Funnel.
	ingressAddrs []netip.Addr

	// now is the clock used for record expiry; tests override it.
	now func() time.Time

	mu      sync.RWMutex
	records map[string][]txtRecord // canonical name -> live TXT values

	servers   []*dns.Server
	conns     []io.Closer
	udpAddr   net.Addr
	tcpAddr   net.Addr
	closeCh   chan struct{}
	closeOnce sync.Once
	closeErr  error
	wg        sync.WaitGroup
}

type txtRecord struct {
	value   string
	expires time.Time
}

// NewACMEChallengeServer creates a DNS server authoritative for zone (the
// MagicDNS base domain). nameserver is the FQDN reported in SOA and NS
// answers. listenAddr is the UDP/TCP address to bind; when empty it defaults
// to ":53". ingressAddrs, if any, are the public addresses of the Funnel
// ingress relay answered for A/AAAA queries of every name below the apex.
func NewACMEChallengeServer(zone, nameserver, listenAddr string, ingressAddrs []netip.Addr) *ACMEChallengeServer {
	if listenAddr == "" {
		listenAddr = ":53"
	}

	return &ACMEChallengeServer{
		zone:         dns.CanonicalName(zone),
		nameserver:   dns.CanonicalName(nameserver),
		listenAddr:   listenAddr,
		ingressAddrs: ingressAddrs,
		now:          time.Now,
		records:      make(map[string][]txtRecord),
		closeCh:      make(chan struct{}),
	}
}

// SetTXT publishes value as a TXT record for name (for example
// "_acme-challenge.host.example.com"). Distinct values for the same name
// coexist so concurrent challenges do not clobber each other; each value is
// retained for acmeRecordTTL after it was last set. The per-name set is
// capped, replacing the value closest to expiry when full.
func (s *ACMEChallengeServer) SetTXT(name, value string) error {
	if !ValidACMEChallengeValue(value) {
		return ErrInvalidACMEChallengeValue
	}

	name = dns.CanonicalName(name)
	now := s.now()
	expires := now.Add(acmeRecordTTL)

	s.mu.Lock()
	defer s.mu.Unlock()

	recs := liveRecords(s.records[name], now)

	for i := range recs {
		if recs[i].value == value {
			recs[i].expires = expires
			s.records[name] = recs

			return nil
		}
	}

	if len(recs) >= maxTXTValuesPerName {
		repl := 0
		for i := 1; i < len(recs); i++ {
			if recs[i].expires.Before(recs[repl].expires) {
				repl = i
			}
		}

		recs[repl] = txtRecord{value: value, expires: expires}
		s.records[name] = recs

		return nil
	}

	s.records[name] = append(recs, txtRecord{value: value, expires: expires})

	return nil
}

// TXT returns the live (non-expired) TXT values published for name.
func (s *ACMEChallengeServer) TXT(name string) []string {
	name = dns.CanonicalName(name)
	now := s.now()

	s.mu.RLock()
	defer s.mu.RUnlock()

	var values []string

	for _, r := range s.records[name] {
		if now.Before(r.expires) {
			values = append(values, r.value)
		}
	}

	return values
}

// liveRecords filters recs in place, keeping the ones that expire after now.
func liveRecords(recs []txtRecord, now time.Time) []txtRecord {
	kept := recs[:0]

	for _, r := range recs {
		if now.Before(r.expires) {
			kept = append(kept, r)
		}
	}

	return kept
}

// Start binds the UDP and TCP listeners, serves queries in the background
// and launches the eviction loop. Binding happens synchronously so an
// unavailable or privileged port is reported here rather than later.
func (s *ACMEChallengeServer) Start() error {
	var lc net.ListenConfig

	pc, err := lc.ListenPacket(context.Background(), "udp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("binding udp listener on %s: %w", s.listenAddr, err)
	}

	l, err := lc.Listen(context.Background(), "tcp", s.listenAddr)
	if err != nil {
		pc.Close()

		return fmt.Errorf("binding tcp listener on %s: %w", s.listenAddr, err)
	}

	s.udpAddr = pc.LocalAddr()
	s.tcpAddr = l.Addr()
	s.conns = []io.Closer{pc, l}

	handler := dns.HandlerFunc(s.serveDNS)
	s.servers = []*dns.Server{
		{PacketConn: pc, Handler: handler, UDPSize: udpMaxSize},
		{Listener: l, Handler: handler},
	}

	for _, srv := range s.servers {
		started := make(chan struct{})
		done := make(chan struct{})

		srv.NotifyStartedFunc = func() { close(started) }

		s.wg.Add(1)

		go func(srv *dns.Server) {
			defer s.wg.Done()
			defer close(done)

			err := srv.ActivateAndServe()
			if err == nil {
				return
			}

			select {
			case <-s.closeCh:
				// Expected: the listener was closed by Close().
			default:
				log.Error().Caller().Err(err).Str("listen_addr", s.listenAddr).
					Msg("ACME challenge DNS server stopped unexpectedly")
			}
		}(srv)

		// Wait until the server is serving so a later Close() always finds
		// it started; the sockets are already bound, so this is immediate.
		select {
		case <-started:
		case <-done:
			_ = s.Close()

			return fmt.Errorf("%w: %s", ErrACMEListenerExited, s.listenAddr)
		}
	}

	s.wg.Add(1)

	go s.cleanupLoop()

	return nil
}

// UDPAddr returns the bound UDP address, or nil before Start.
func (s *ACMEChallengeServer) UDPAddr() net.Addr {
	return s.udpAddr
}

// TCPAddr returns the bound TCP address, or nil before Start.
func (s *ACMEChallengeServer) TCPAddr() net.Addr {
	return s.tcpAddr
}

// Close shuts down the listeners and stops the eviction loop. It is safe to
// call multiple times and before Start.
func (s *ACMEChallengeServer) Close() error {
	s.closeOnce.Do(func() {
		close(s.closeCh)

		var errs []error

		for _, srv := range s.servers {
			err := srv.Shutdown()
			if err != nil {
				errs = append(errs, err)
			}
		}

		// Shutdown only closes a server that finished starting; close
		// the sockets as well so nothing outlives us if Start() bailed
		// out half-way. A double close is harmless.
		for _, c := range s.conns {
			_ = c.Close()
		}

		s.wg.Wait()

		s.closeErr = errors.Join(errs...)
	})

	return s.closeErr
}

func (s *ACMEChallengeServer) cleanupLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(acmeCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.closeCh:
			return
		case <-ticker.C:
			s.evictExpired()
		}
	}
}

func (s *ACMEChallengeServer) evictExpired() {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	for name, recs := range s.records {
		kept := liveRecords(recs, now)
		if len(kept) == 0 {
			delete(s.records, name)
		} else {
			s.records[name] = kept
		}
	}
}

// serveDNS answers queries for the delegated zone. It is authoritative: it
// serves the apex SOA/NS, the published challenge TXT records and, when
// ingress addresses are configured, A/AAAA for every name below the apex.
// It returns NODATA (NOERROR with the SOA in the authority section) for any
// other in-zone name or type, including the CAA lookups a CA performs before
// issuance. Queries outside the zone are refused.
func (s *ACMEChallengeServer) serveDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = false

	if r.Opcode != dns.OpcodeQuery {
		m.Authoritative = false
		m.SetRcode(r, dns.RcodeNotImplemented)
		s.respond(w, r, m)

		return
	}

	if len(r.Question) != 1 {
		m.Authoritative = false
		m.SetRcode(r, dns.RcodeFormatError)
		s.respond(w, r, m)

		return
	}

	q := r.Question[0]
	qname := dns.CanonicalName(q.Name)

	if !dns.IsSubDomain(s.zone, qname) {
		m.Authoritative = false
		m.SetRcode(r, dns.RcodeRefused)
		s.respond(w, r, m)

		return
	}

	switch {
	case q.Qtype == dns.TypeSOA && qname == s.zone:
		m.Answer = append(m.Answer, s.soa())
	case q.Qtype == dns.TypeNS && qname == s.zone:
		m.Answer = append(m.Answer, s.ns())
	case q.Qtype == dns.TypeTXT:
		// One TXT RR per value so a resolver sees independent records
		// rather than one concatenated string.
		for _, v := range s.TXT(qname) {
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    acmeAnswerTTL,
				},
				Txt: []string{v},
			})
		}
	case q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA:
		m.Answer = append(m.Answer, s.ingress(qname, q.Qtype)...)
	}

	if len(m.Answer) == 0 {
		m.Ns = append(m.Ns, s.soa())
	}

	s.respond(w, r, m)
}

// respond echoes EDNS0 when the client offered it, truncates UDP answers to
// the negotiated size and writes the message.
func (s *ACMEChallengeServer) respond(w dns.ResponseWriter, r, m *dns.Msg) {
	size := udpMinSize

	if opt := r.IsEdns0(); opt != nil {
		size = min(max(int(opt.UDPSize()), udpMinSize), udpMaxSize)
		m.SetEdns0(udpMaxSize, false)
	}

	if w.RemoteAddr() != nil && w.RemoteAddr().Network() == "udp" {
		m.Truncate(size)
	}

	err := w.WriteMsg(m)
	if err != nil {
		log.Debug().Caller().Err(err).Msg("writing ACME challenge DNS response")
	}
}

// ingress returns the A or AAAA records pointing qname at the Funnel
// ingress relay. It behaves like a wildcard: every name below the apex
// resolves, whatever its depth. The apex itself is excluded (it is the
// zone, not a node) and so is the nameserver when it lives inside the zone:
// its address is the parent zone's glue for this server, not the relay.
func (s *ACMEChallengeServer) ingress(qname string, qtype uint16) []dns.RR {
	if len(s.ingressAddrs) == 0 || qname == s.zone || qname == s.nameserver {
		return nil
	}

	var rrs []dns.RR

	for _, addr := range s.ingressAddrs {
		hdr := dns.RR_Header{
			Name:   qname,
			Rrtype: qtype,
			Class:  dns.ClassINET,
			Ttl:    ingressAnswerTTL,
		}

		switch {
		case qtype == dns.TypeA && addr.Is4():
			rrs = append(rrs, &dns.A{Hdr: hdr, A: addr.AsSlice()})
		case qtype == dns.TypeAAAA && addr.Is6():
			rrs = append(rrs, &dns.AAAA{Hdr: hdr, AAAA: addr.AsSlice()})
		}
	}

	return rrs
}

func (s *ACMEChallengeServer) soa() *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   s.zone,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    acmeZoneTTL,
		},
		Ns:      s.nameserver,
		Mbox:    "hostmaster." + s.zone,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  60,
	}
}

func (s *ACMEChallengeServer) ns() *dns.NS {
	return &dns.NS{
		Hdr: dns.RR_Header{
			Name:   s.zone,
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    acmeZoneTTL,
		},
		Ns: s.nameserver,
	}
}
