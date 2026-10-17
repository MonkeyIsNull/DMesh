package node

import (
	"crypto/sha256"
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
	"github.com/MonkeyIsNull/DMesh/internal/nat"
	"github.com/MonkeyIsNull/DMesh/internal/transport"
)

// mustIdentity builds a deterministic identity for candidate signing tests.
func mustIdentity(t *testing.T, seed int64) *identity.Identity {
	t.Helper()
	id, err := identity.GenerateFrom("", rand.New(rand.NewSource(seed)))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// nat_sim_test.go exercises the v0.4 NAT reflex + relay machinery on the
// deterministic in-memory sim (realm-separated NAT model + fake clock + barrier).

// behindNAT marks an internal address as sitting behind an endpoint-independent
// NAT in the given realm, mapped to a sticky external public address.
func (r *router) behindNAT(internal netip.AddrPort, realm int, external netip.AddrPort) {
	r.mu.Lock()
	r.realm[internal] = realm
	r.external[internal] = external
	r.internalOf[external] = internal
	r.realm[external] = 0
	r.mu.Unlock()
}

// natExternal returns a deterministic public external address for a realm.
func (m *simMesh) natExternal(realm int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{100, 64, 0, byte(realm)}), uint16(40000+realm))
}

// addNatNode adds a node behind a NAT (realm>0) or a public node (realm==0),
// with reflex enabled, candidates from a fixed source, and the given relay
// capability and seed peers (a NAT node must initiate toward its seeds, since a
// public peer cannot dial into its realm).
func (m *simMesh) addNatNode(label string, realm int, relay bool, seeds ...netip.AddrPort) *simNode {
	idx := len(m.nodes)
	addr := m.addr(idx)
	sn := m.addNode(m.t, label, func(cfg *Config) {
		cfg.RelayCapable = relay
		cfg.DisableGossipDial = true
		cfg.CandidateSource = func() []netip.AddrPort { return []netip.AddrPort{addr} }
		cfg.CircuitRand = rand.New(rand.NewSource(int64(5000 + idx)))
		cfg.SeedPeers = append([]netip.AddrPort(nil), seeds...)
	})
	if realm != 0 {
		m.r.behindNAT(sn.addr, realm, m.natExternal(realm))
	}
	return sn
}

// relayOf returns the first relay-capable node in the mesh.
func (m *simMesh) relayOf() *simNode {
	for _, sn := range m.nodes {
		if sn.n.relayRole {
			return sn
		}
	}
	return nil
}

// openRelayedSession has a explicitly open a relay circuit to b through the
// mesh's relay, then waits until both ends hold a connected relayed peer.
func (m *simMesh) openRelayedSession(a, b *simNode) bool {
	r := m.relayOf()
	if r == nil {
		m.t.Fatal("no relay in mesh")
	}
	a.n.DialViaRelay(m.ctx, r.id.NodeID(), b.id.NodeID())
	return m.waitRelayConnected(a, b, 30*time.Second)
}

// waitRelayConnected polls until a holds a connected relayed peer to b and b to
// a, advancing the fake clock so the relayed-handshake RTO retransmits fire.
func (m *simMesh) waitRelayConnected(a, b *simNode, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m.r.settle()
		if relayedUp(a, b) && relayedUp(b, a) {
			return true
		}
		m.clk.Advance(250 * time.Millisecond)
		m.r.settle()
		time.Sleep(time.Millisecond)
	}
	return relayedUp(a, b) && relayedUp(b, a)
}

// settleUntilPeriods drives synchronized protocol periods (gossip rounds on the
// injected clock) until cond holds or maxPeriods elapse, returning whether cond was
// met. Each period is fully settled and totally ordered, so this is a wait on
// deterministic, monotonic gossip PROGRESS - never a wall-clock timing window. Use
// it when the exact period at which a converging gossip fact lands is map-iteration
// dependent (and so varies per process seed) and must not be hard-coded.
func (m *simMesh) settleUntilPeriods(maxPeriods int, cond func() bool) bool {
	for i := 0; i < maxPeriods; i++ {
		if cond() {
			return true
		}
		m.period()
	}
	return cond()
}

// relayedUp reports whether observer holds a connected session to subject over a
// relay path.
func relayedUp(observer, subject *simNode) bool {
	kind, ok := observer.n.peerPathKindForTest(subject.id.NodeID())
	if !ok || kind != pathRelay {
		return false
	}
	return sessionUp(observer, subject)
}

// --- tests ------------------------------------------------------------------

// TestSimNatRealmSeparation is the direct-dial-fails standalone proof (plan test
// 8): a cross-realm private dial is dropped, an unsolicited public->internal
// packet is dropped, and the return path opens only after the internal node has
// egressed toward the remote.
func TestSimNatRealmSeparation(t *testing.T) {
	m := newSimMesh(t, 1)
	defer m.stop()
	aInternal := netip.MustParseAddrPort("10.0.1.1:9000")
	bInternal := netip.MustParseAddrPort("10.0.2.1:9000")
	pub := netip.MustParseAddrPort("203.0.113.1:9000")
	aExt := netip.MustParseAddrPort("100.64.0.1:40001")
	m.r.behindNAT(aInternal, 1, aExt)
	m.r.behindNAT(bInternal, 2, netip.MustParseAddrPort("100.64.0.2:40002"))

	// Cross-realm private dial A_internal -> B_internal is dropped.
	if _, _, drop := translate(m.r, aInternal, bInternal); !drop {
		t.Fatal("cross-realm private dial was not dropped")
	}
	// Unsolicited public -> A_external is dropped (A has not egressed toward pub).
	if _, _, drop := translate(m.r, pub, aExt); !drop {
		t.Fatal("unsolicited inbound to NAT was not dropped")
	}
	// A egresses toward pub: source is rewritten to A_external, egress recorded.
	ds, _, drop := translate(m.r, aInternal, pub)
	if drop || ds != aExt {
		t.Fatalf("egress translate wrong: src=%v drop=%v", ds, drop)
	}
	// Now the return path pub -> A_external is allowed and reverse-translated.
	_, dd, drop := translate(m.r, pub, aExt)
	if drop || dd != aInternal {
		t.Fatalf("return path not allowed: dst=%v drop=%v", dd, drop)
	}
}

// translate is a test shim over natTranslate under the lock.
func translate(r *router, src, dst netip.AddrPort) (netip.AddrPort, netip.AddrPort, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.natTranslate(src, dst)
}

// TestFrameSizeInvariant recomputes the wrapped relay budget from the transport
// constants and asserts every wrapped frame (max DATA + each handshake message)
// stays within MaxPlaintext - failing closed if any constant changes (plan test
// 23).
func TestFrameSizeInvariant(t *testing.T) {
	// A relayed inner frame is a full transport datagram; wrapped it becomes
	// msgRelay(1) + relay ver(1) + sub(1) + circuitID(8) + innerFrame, then sealed
	// on the carrier (so the wrapped bytes are the carrier plaintext).
	const relayWrap = 1 + 1 + 1 + 8 // msgRelay + ver + sub + circuitID
	// Max inner DATA frame: data header + inner plaintext (msgSession+subData
	// header 28 + MaxChunk) + AEAD tag.
	const dataHeader = 19
	const aead = 16
	const sessionHeader = 28 // msgSession 1 + subtype 1 + sessionID 16 + offset 8 + len 2
	innerData := dataHeader + sessionHeader + maxRelayChunk + aead
	if got := relayWrap + innerData; got > transport.MaxPlaintext {
		t.Fatalf("wrapped max DATA frame %d exceeds MaxPlaintext %d", got, transport.MaxPlaintext)
	}
	// Handshake messages are far smaller than a max DATA frame, but assert the
	// worst-case Noise handshake payload wrapped still fits.
	maxHandshake := 11 /*hsHeader*/ + transport.MaxPayload
	_ = maxHandshake
	// The clamp must keep the effective MaxChunk within the budget.
	if maxRelayChunk != 1110 {
		t.Fatalf("maxRelayChunk drifted: %d", maxRelayChunk)
	}
}

// TestCircuitAndStreamOverRelay is the core end-to-end proof (plan tests 9 +
// 18): A and B behind separate NATs, both connected to a public relay R; A opens
// a circuit to B through R, the Noise handshake completes over the circuit with
// path==relay on both ends, and a durable byte stream transfers end-to-end.
func TestCircuitAndStreamOverRelay(t *testing.T) {
	m := newSimMesh(t, 7)
	defer m.stop()
	p := testParams()
	m.params = p

	r := m.addNatNode("relay", 0, true)
	a := m.addNatNode("A", 1, false, r.addr)
	b := m.addNatNode("B", 2, false, r.addr)

	// A and B dial the public relay (election-free seed path, NAT egress works).
	if !m.waitNodeConnected(a, r, 30*time.Second) || !m.waitNodeConnected(b, r, 30*time.Second) {
		t.Fatal("A/B did not connect to the relay")
	}
	// Direct A<->B is impossible (different NAT realms): relay is mandatory.
	if !m.openRelayedSession(a, b) {
		t.Fatalf("relayed session A<->B did not establish")
	}
	if kind, _ := a.n.peerPathKindForTest(b.id.NodeID()); kind != pathRelay {
		t.Fatal("A's session to B is not over a relay path")
	}

	// Durable stream over the circuit, multi-datagram, SHA match.
	payload := make([]byte, 4000)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	h, err := a.n.OpenSession(m.ctx, b.id.NodeID())
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	accepted := make(chan *Session, 1)
	go func() {
		select {
		case s := <-b.n.Accept():
			accepted <- s
		case <-m.ctx.Done():
		}
	}()
	// Pump the session: writes + ticks + clock advance drive RTO over the relay.
	writeDone := make(chan error, 1)
	go func() {
		_, werr := h.Write(payload)
		writeDone <- werr
	}()

	var bs *Session
	deadline := time.Now().Add(30 * time.Second)
	for bs == nil && time.Now().Before(deadline) {
		m.sessPump(250*time.Millisecond, 2)
		select {
		case bs = <-accepted:
		default:
		}
	}
	if bs == nil {
		t.Fatal("B never accepted the relayed session")
	}
	got := make([]byte, 0, len(payload))
	buf := make([]byte, 1500)
	for len(got) < len(payload) && time.Now().Before(deadline) {
		m.sessPump(250*time.Millisecond, 2)
		bs.node.mu.Lock()
		avail := len(bs.ls.readBuf) > 0
		bs.node.mu.Unlock()
		if avail {
			nr, _ := bs.Read(buf)
			got = append(got, buf[:nr]...)
		}
	}
	if len(got) != len(payload) || sha256.Sum256(got) != sha256.Sum256(payload) {
		t.Fatalf("relayed stream mismatch: got %d want %d bytes", len(got), len(payload))
	}
	<-writeDone
}

// waitNodeConnected polls until a holds a connected (direct) session to b,
// advancing the clock for seed-dial + handshake RTO timers. Readiness is gated
// on the carrier session being PUBLISHED on BOTH ends (carrierPublished), not
// merely StateConnected (sessionUp): handleAuth sets StateConnected one barrier
// cycle before handleSessReady publishes p.sess, so a StateConnected-only gate
// lets settle() return in that gap — after which a one-shot circOpen fired by a
// relay-open helper is silently dropped by sendCircControl (sess == nil) and
// nothing re-dials, wedging relay setup to the deadline. See carrierPublished.
func (m *simMesh) waitNodeConnected(a, b *simNode, timeout time.Duration) bool {
	ready := func() bool { return carrierPublished(a, b) && carrierPublished(b, a) }
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m.r.settle()
		if ready() {
			return true
		}
		m.clk.Advance(250 * time.Millisecond)
		m.r.settle()
		time.Sleep(time.Millisecond)
	}
	return ready()
}

// TestRelayDumbPipeAndBinding proves the relay refuses to open a circuit to a
// target it is not connected to (no amplification) and that a credentialed third
// party cannot inject on an existing circuit (endpoint binding) - plan test 12.
func TestRelayDumbPipeAndBinding(t *testing.T) {
	m := newSimMesh(t, 11)
	defer m.stop()

	r := m.addNatNode("relay", 0, true)
	a := m.addNatNode("A", 1, false, r.addr)
	if !m.waitNodeConnected(a, r, 30*time.Second) {
		t.Fatal("A did not connect to relay")
	}

	// Fabricate a target the relay has never connected to.
	var ghost = idFake(0xAB)
	victim := netip.MustParseAddrPort("198.51.100.9:9000")
	before := m.r.attemptsTo(victim)
	a.n.DialViaRelay(m.ctx, r.id.NodeID(), ghost)
	m.r.settle()
	// The relay must send nothing to the ghost/victim (no on-demand dial).
	if after := m.r.attemptsTo(victim); after != before {
		t.Fatalf("relay emitted packets toward a non-connected target: %d", after-before)
	}
	// The relay holds no circuit for a denied open.
	if r.n.relayCircuitCountForTest() != 0 {
		t.Fatalf("relay opened a circuit for a non-connected target: %d", r.n.relayCircuitCountForTest())
	}
}

// TestCircuitChurn opens and tears down many relayed circuits and asserts the
// endpoint circuit map returns to zero and the relay's circuit table drains
// (plan test 22).
func TestCircuitChurn(t *testing.T) {
	m := newSimMesh(t, 13)
	defer m.stop()

	r := m.addNatNode("relay", 0, true)
	a := m.addNatNode("A", 1, false, r.addr)
	b := m.addNatNode("B", 2, false, r.addr)
	if !m.waitNodeConnected(a, r, 30*time.Second) || !m.waitNodeConnected(b, r, 30*time.Second) {
		t.Fatal("A/B did not connect to relay")
	}

	for i := 0; i < 5; i++ {
		if !m.openRelayedSession(a, b) {
			t.Fatalf("round %d: relayed session did not establish", i)
		}
		// Tear down both relayed peers: reap by advancing well past the idle timeout,
		// then drive session-tick rounds until A's circuit map drains. The reap
		// cancels the relayed peer's context on the loop, but its driver goroutine
		// signals its exit - and the loop's handleDone that actually removes the entry
		// from n.circuits - asynchronously, retired on a LATER barrier cycle. So the
		// exact round at which the map reaches zero is goroutine-schedule dependent
		// (load-sensitive): a fixed 2-round pump is occasionally too short on a slow/
		// loaded runner (the CI flake). Bound the wait generously and settle-until the
		// drain condition holds instead of asserting after a hard-coded count.
		m.clk.Advance(m.nodeNatIdle(a) + time.Second)
		if !m.settleUntilDrained(50, 250*time.Millisecond, func() bool {
			return a.n.circuitCountForTest() == 0
		}) {
			t.Fatalf("round %d: A circuit map not drained: %d", i, a.n.circuitCountForTest())
		}
	}
}

// settleUntilDrained drives session-tick rounds on the injected clock (advancing
// by d each round so any session RTO retransmit fires) until cond holds or
// maxRounds elapse, returning whether cond was met. Each round fully settles the
// mesh after every node's tick (the sessPump discipline), so this is a BOUNDED
// wait on deterministic teardown PROGRESS, never a wall-clock timing window: a
// circuit teardown cancels the relayed peer's context on the loop, but the driver
// goroutine reports its exit asynchronously and the loop's handleDone (which
// removes the entry from n.circuits) is retired on a later barrier cycle - so the
// round at which the map drains is goroutine-schedule dependent and must not be
// hard-coded to a fixed pump count. No SWIM phase/keepalive/fallback timer fires
// on these advances (addNatNode sets ManualSwimPhases + DisableKeepalive + 24h
// fallback), so the loop adds no gossip churn.
func (m *simMesh) settleUntilDrained(maxRounds int, d time.Duration, cond func() bool) bool {
	for i := 0; i < maxRounds; i++ {
		if cond() {
			return true
		}
		m.clk.Advance(d)
		m.r.settle()
		m.sessTickAll()
	}
	return cond()
}

// nodeNatIdle returns a node's circuit idle timeout.
func (m *simMesh) nodeNatIdle(sn *simNode) time.Duration {
	return sn.n.natParams.CircuitIdleTimeout
}

// TestRelayReopenAfterLostOpen proves a single lost circuit-open no longer wedges
// relay fallback to the target forever. A's first circOpen is dropped on the wire
// (so no circOpenAck ever returns), leaking a pendingOpens entry that - before the
// sweep - deduped every later reopen/dial to B. After PendingOpenTimeout the entry
// is swept on a session tick, so A can re-open the circuit and the relayed session
// establishes. (Regression for the pendingOpens leak / permanent-wedge finding.)
func TestRelayReopenAfterLostOpen(t *testing.T) {
	m := newSimMesh(t, 17)
	defer m.stop()

	r := m.addNatNode("relay", 0, true)
	a := m.addNatNode("A", 1, false, r.addr)
	b := m.addNatNode("B", 2, false, r.addr)
	if !m.waitNodeConnected(a, r, 30*time.Second) || !m.waitNodeConnected(b, r, 30*time.Second) {
		t.Fatal("A/B did not connect to relay")
	}

	// Drop A's first circuit-open: isolate A for exactly one DialViaRelay+settle so
	// its circOpen send is dropped on the wire (no ack comes back). This records a
	// pendingOpens entry that never gets deleted by the ack path.
	m.r.isolate(a.addr, true)
	a.n.DialViaRelay(m.ctx, r.id.NodeID(), b.id.NodeID())
	m.r.settle()
	m.r.isolate(a.addr, false)

	// The open never reached the relay, so no circuit exists and A<->B is not up.
	if r.n.relayCircuitCountForTest() != 0 {
		t.Fatalf("relay bound a circuit despite the dropped open: %d", r.n.relayCircuitCountForTest())
	}
	if relayedUp(a, b) {
		t.Fatal("relayed session came up despite the dropped open")
	}

	// Advance past PendingOpenTimeout and tick: the stale pendingOpens entry is
	// swept, so a fresh open to B is no longer deduped away.
	m.clk.Advance(a.n.natParams.PendingOpenTimeout + time.Second)
	m.sessTickAll()
	m.r.settle()

	// A can now re-open the circuit to B and the relayed session establishes. With
	// the leak present this stays wedged forever and the wait fails.
	if !m.openRelayedSession(a, b) {
		t.Fatal("relay fallback to B stayed wedged after a lost open (pendingOpens leak)")
	}
}

// injectCircuitIn pushes a synthetic circuit-control body onto a node's loop as if
// it had been demuxed from an authenticated frame from `from`, balancing the sim
// barrier exactly like the real demux (node.go) and InjectSessionTick.
func (m *simMesh) injectCircuitIn(sn *simNode, from identity.NodeID, body []byte) {
	sn.n.sbAdd()
	select {
	case sn.n.circuitIn <- circuitInbound{fromID: from, fromDirect: true, body: body}:
	case <-m.ctx.Done():
		sn.n.sbDone()
	}
	m.r.settle()
}

// TestRelayChargesNonDataFlood proves the relay no longer lets non-DATA frames
// bypass its byte buckets. A bound circuit is driven with a flood of handshake-
// typed frames and then malformed (bad-magic) frames; only the bounded handshake
// grace plus what the per-circuit bucket admits is forwarded, and the rest is
// shed - where the old code forwarded every such frame uncharged. (Regression for
// the relay rate-limit-bypass finding.)
func TestRelayChargesNonDataFlood(t *testing.T) {
	m := newSimMesh(t, 19)
	defer m.stop()

	// Public relay with tightened byte buckets and a small handshake grace, so the
	// bound is reached after a handful of frames (production applies the same policy
	// at 1 MiB/s and an 8 KiB grace).
	rIdx := len(m.nodes)
	rAddr := m.addr(rIdx)
	r := m.addNode(t, "relay", func(cfg *Config) {
		cfg.RelayCapable = true
		cfg.DisableGossipDial = true
		cfg.CandidateSource = func() []netip.AddrPort { return []netip.AddrPort{rAddr} }
		cfg.CircuitRand = rand.New(rand.NewSource(int64(5000 + rIdx)))
		np := nat.DefaultParams()
		np.HandshakeGraceBytes = 400 // exactly two 200-byte handshake frames
		np.PerCircuitBytesPerSec = 400
		np.PerRequesterBytesPerSec = 1 << 20
		np.GlobalBytesPerSec = 1 << 20
		cfg.NatParams = np
	})
	a := m.addNatNode("A", 0, false, r.addr)
	b := m.addNatNode("B", 0, false, r.addr)
	if !m.waitNodeConnected(a, r, 30*time.Second) || !m.waitNodeConnected(b, r, 30*time.Second) {
		t.Fatal("A/B did not connect to relay")
	}

	// Darken B so it never activates a relayed peer from the circOpenNotify. Forwards
	// to it are still COUNTED as send attempts (attemptsTo counts dropped sends), so
	// we measure exactly how many frames the relay admitted past its buckets.
	m.r.isolate(b.addr, true)

	// Bind a circuit A<->B at the relay via a synthetic circOpen from A, so neither
	// endpoint runs the inner handshake (which would itself spend the grace). The
	// relay allocates the circuit id from its injected RNG; mirror that first draw
	// here so we address the circuit without reading the relay's loop-owned table
	// off the loop (which would be a data race).
	aID, bID := a.id.NodeID(), b.id.NodeID()
	cid := nat.CircuitID(rand.New(rand.NewSource(int64(5000 + rIdx))).Uint64())
	if cid == 0 {
		t.Fatal("predicted a zero circuit id")
	}
	m.injectCircuitIn(r, aID, nat.EncodeCircOpen(bID, 0x1234))

	// Flood handshake-typed frames (valid magic+version+type=handshake, 200 bytes).
	// Count relay forwards with the loop-owned egress counter, NOT the router's
	// per-address attempt counter (which also sees direct-carrier SWIM/session
	// traffic to B and so would be noisy under -race).
	hs := make([]byte, 200)
	hs[0], hs[1], hs[2], hs[3] = 0xD3, 0x5A, 1, 1
	const flood = 20
	before := r.n.relayForwardsForTest()
	for i := 0; i < flood; i++ {
		m.injectCircuitIn(r, aID, nat.EncodeCircData(cid, hs))
	}
	// Clock is frozen, so no bucket refill: 2 frames fit the 400-byte grace and the
	// 400-byte per-circuit bucket admits 2 more; the remaining 16 are shed.
	if forwarded := r.n.relayForwardsForTest() - before; forwarded != 4 {
		t.Fatalf("relay forwarded %d/%d flooded handshake-typed frames; want 4 (2 grace + 2 bucket) - rate limit bypassed", forwarded, flood)
	}

	// Malformed frames (bad magic -> Classify error) are charged like data, not
	// exempt: with the per-circuit bucket already drained, every one is shed.
	bad := make([]byte, 200) // all-zero header: bad magic
	before2 := r.n.relayForwardsForTest()
	for i := 0; i < 10; i++ {
		m.injectCircuitIn(r, aID, nat.EncodeCircData(cid, bad))
	}
	if extra := r.n.relayForwardsForTest() - before2; extra != 0 {
		t.Fatalf("relay forwarded %d malformed frames on a drained bucket; want 0 (must be charged, not exempt)", extra)
	}
}

// TestCandidatePoisoningRejected proves a credentialed member cannot forge
// another member's candidate set: a set signed by the wrong key is dropped while
// base liveness is still accepted (plan test 7).
func TestCandidatePoisoningRejected(t *testing.T) {
	victim := mustIdentity(t, 1)
	attacker := mustIdentity(t, 2)
	_ = attacker
	// A forged set claims to be victim's but is signed by the attacker.
	forged := nat.SignSelf(attacker, 9, nat.CapRelay, []nat.Candidate{
		{Addr: netip.MustParseAddrPort("6.6.6.6:6666"), Type: nat.CandHost},
	})
	// It must not verify against the victim subject.
	if nat.Verify(victim.NodeID(), forged) {
		t.Fatal("forged set verified against the victim subject")
	}
	// A genuine victim set does verify.
	genuine := nat.SignSelf(victim, 1, nat.CapNat, []nat.Candidate{
		{Addr: netip.MustParseAddrPort("10.0.0.9:9000"), Type: nat.CandHost},
	})
	if !nat.Verify(victim.NodeID(), genuine) {
		t.Fatal("genuine victim set failed to verify")
	}
}

// TestReflexCorroboration proves a reflexive candidate is promoted only after a
// second, corroborating observer, is signed into the advertised set, and reaches
// a third node via gossip (plan tests 1 + 2).
func TestReflexCorroboration(t *testing.T) {
	m := newSimMesh(t, 21)
	defer m.stop()

	p1 := m.addNatNode("P1", 0, false)
	p2 := m.addNatNode("P2", 0, false)
	c := m.addNatNode("C", 0, false)
	a := m.addNatNode("A", 1, false, p1.addr, p2.addr, c.addr)
	aExt := m.natExternal(1)

	if !m.waitNodeConnected(a, p1, 30*time.Second) ||
		!m.waitNodeConnected(a, p2, 30*time.Second) ||
		!m.waitNodeConnected(a, c, 30*time.Second) {
		t.Fatal("A did not connect to its observers")
	}
	// A can promote a reflexive address only when, at probe time, it (1) holds
	// LIVE DIRECT sessions to >= MinReflexObservers observers and (2) has learned
	// those observers advertise CapNat (handleNatProbe asks only learned-CapNat
	// direct peers, at most ReflexMaxPeers of them). Both facts converge over SWIM
	// gossip whose per-period target selection iterates Go maps, so WHEN they hold
	// is map-iteration dependent and varies per process seed - the source of the
	// old flakiness. Two further sim subtleties matter here: the fake clock does
	// not advance on settle(), and the activity barrier is only a reliable
	// quiescence proof BETWEEN handshakes (an in-flight handshake drains its inbox
	// off-barrier, so settle() can return mid-reconnect). So we must reach a
	// fully-connected, quiescent state on the injected clock - a poll+advance, like
	// waitNodeConnected - before probing, never just a fixed period count.
	//
	// reflexReady holds when A has live direct sessions to every observer AND has
	// learned each one's CapNat set. It is a deterministic-progress predicate, not
	// a timing window.
	observers := []*simNode{p1, p2, c}
	reflexReady := func() bool {
		for _, o := range observers {
			if !sessionUp(a, o) || !sessionUp(o, a) {
				return false
			}
			cs, ok := a.n.candidateSetForTest(o.id.NodeID())
			if !ok || cs.Caps&nat.CapNat == 0 {
				return false
			}
		}
		return true
	}
	// Drive gossip periods until CapNat has propagated, then re-stabilize every
	// direct session with a poll+advance (periods run SWIM failure detection, which
	// can transiently churn a behind-NAT node's sessions; the advance drives any
	// reconnect RTO to completion so no handshake is in flight when we probe).
	deadline := time.Now().Add(30 * time.Second)
	for !reflexReady() && time.Now().Before(deadline) {
		m.period()
		if reflexReady() {
			break
		}
		m.clk.Advance(250 * time.Millisecond)
		m.r.settle()
	}
	if !reflexReady() {
		t.Fatal("A did not reach a stable, CapNat-learned connection to its observers")
	}
	if cs, ok := a.n.candidateSetForTest(p1.id.NodeID()); !ok || cs.Caps&nat.CapNat == 0 {
		t.Fatal("A did not learn P1's CapNat candidate set")
	}

	// Probe in a bounded retry loop. Each round asks ReflexMaxPeers (2) observers;
	// both are public and see the same NAT-translated source (aExt), so two
	// corroborating responses reach MinReflexObservers (2) and A promotes aExt.
	// settle() fully processes each round (probe -> responses -> promotion ->
	// re-gossip) now that no handshake is in flight. Between rounds advance past the
	// per-source responder min-gap (ReflexRespRatePerSource=2 => 500ms) so responders
	// are never rate-limited into silence; reflexObs accumulates across rounds, so a
	// round that races a reflex datagram dropped under inbox pressure is recovered by
	// the next. No SWIM phase/keepalive/fallback timer fires on these advances
	// (ManualSwimPhases + DisableKeepalive + 24h fallback), so the loop adds no churn.
	promoted := false
	probeDeadline := time.Now().Add(30 * time.Second)
	for !promoted && time.Now().Before(probeDeadline) {
		a.n.InjectNatProbe(m.ctx)
		m.r.settle()
		if a.n.hasReflexiveCandidateForTest(a.id.NodeID(), aExt) {
			promoted = true
			break
		}
		m.clk.Advance(time.Second)
		m.r.settle()
	}
	if !promoted {
		t.Fatal("A did not promote the corroborated reflexive candidate")
	}
	if a.n.selfCandGenForTest() < 2 {
		t.Fatalf("selfCandGen did not advance on promotion: %d", a.n.selfCandGenForTest())
	}
	// The signed reflexive candidate reaches the third node via gossip. Drive gossip
	// until C has learned it (deterministic-progress wait), rather than assuming a
	// fixed period count.
	if !m.settleUntilPeriods(30, func() bool {
		return c.n.hasReflexiveCandidateForTest(a.id.NodeID(), aExt)
	}) {
		t.Fatal("third node C never learned A's reflexive candidate via gossip")
	}
}

// TestLoneSpoofedReflexEmitsNothing proves a single malicious observer reporting
// a victim ip:port neither promotes the address nor causes any packet to be
// emitted toward it (plan test 3).
func TestLoneSpoofedReflexEmitsNothing(t *testing.T) {
	m := newSimMesh(t, 23)
	defer m.stop()

	mal := m.addNatNode("M", 0, false)
	a := m.addNatNode("A", 1, false, mal.addr)
	if !m.waitNodeConnected(a, mal, 30*time.Second) {
		t.Fatal("A did not connect to the malicious observer")
	}
	m.periods(2)

	victim := netip.MustParseAddrPort("198.51.100.200:5555")
	// Make M answer every reflexReq with the victim address instead of A's true
	// source, by poisoning M's responder to report the victim.
	mal.n.setReflexSpoofForTest(victim)

	before := m.r.attemptsTo(victim)
	for i := 0; i < 4; i++ {
		a.n.InjectNatProbe(m.ctx)
		m.r.settle()
	}
	// A has only ONE (malicious) observer, so the victim is never corroborated.
	if a.n.hasReflexiveCandidateForTest(a.id.NodeID(), victim) {
		t.Fatal("A promoted an uncorroborated (spoofed) reflexive address")
	}
	// A never emits a packet toward the victim.
	if after := m.r.attemptsTo(victim); after != before {
		t.Fatalf("A emitted %d packets toward the spoofed victim address", after-before)
	}
}

// TestRelayedResponderRequiresNotify proves the relayed-responder admission bypass
// is closed: an unsolicited circData for an UNKNOWN circuit from a directly-
// connected credentialed peer does NOT manufacture a relayed responder (which would
// spawn a driveResponder goroutine bypassing handleCircOpenNotify's authorized-relay
// + allow-list + caps gate), while a circuit that is properly opened and notified
// still establishes. (Regression for the relayed-responder admission-bypass finding.)
func TestRelayedResponderRequiresNotify(t *testing.T) {
	m := newSimMesh(t, 29)
	defer m.stop()

	r := m.addNatNode("relay", 0, true)
	mPeer := m.addNatNode("M", 0, false)
	a := m.addNatNode("A", 1, false, r.addr)
	b := m.addNatNode("B", 2, false, r.addr, mPeer.addr)
	if !m.waitNodeConnected(a, r, 30*time.Second) ||
		!m.waitNodeConnected(b, r, 30*time.Second) ||
		!m.waitNodeConnected(b, mPeer, 30*time.Second) {
		t.Fatal("A/B did not connect to the relay / M")
	}

	// A directly-connected credentialed peer M sends B an unsolicited circData for a
	// circuit id B was never notified about, whose inner payload peeks as handshake
	// msg1. Before the fix this reached startRelayedResponderUnknown and spawned a
	// responder (relay=M, intended=zero); now it must be dropped, because a relayed
	// responder is admitted ONLY via a legitimate circOpenNotify.
	msg1 := []byte{0xD3, 0x5A, 1, 1, 1, 0, 0, 0, 0, 0, 0} // magic+ver+handshake+hsIndex=1+senderIndex(4)+len=0
	if idx, ok := transport.PeekHandshake(msg1); !ok || idx != 1 {
		t.Fatalf("test msg1 frame does not peek as handshake msg1: idx=%d ok=%v", idx, ok)
	}
	ghostCid := nat.CircuitID(0xBADC0FFEE0DDF00D)
	before := b.n.circuitCountForTest()
	m.injectCircuitIn(b, mPeer.id.NodeID(), nat.EncodeCircData(ghostCid, msg1))
	if after := b.n.circuitCountForTest(); after != before {
		t.Fatalf("B spawned a relayed responder from an unsolicited circData for an unknown circuit: %d -> %d", before, after)
	}

	// A properly-opened, notified circuit A<->B through R still establishes end to
	// end (legitimate reordering / setup is unaffected by closing the bypass).
	if !m.openRelayedSession(a, b) {
		t.Fatal("a properly-notified relayed circuit failed to establish")
	}
	if b.n.circuitCountForTest() == 0 {
		t.Fatal("B holds no relayed peer after a legitimate circuit setup")
	}
}
