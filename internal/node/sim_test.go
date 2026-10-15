package node

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/clock"
	"github.com/MonkeyIsNull/DMesh/internal/discovery"
	"github.com/MonkeyIsNull/DMesh/internal/identity"
	"github.com/MonkeyIsNull/DMesh/internal/swim"
	"github.com/MonkeyIsNull/DMesh/internal/transport"
)

// sim_test.go is the deterministic, offline, loopback-free in-memory network
// used by every SWIM integration test. It needs no real UDP, multicast, or
// second machine. See §10 of the design plan.
//
// Determinism strategy (the robust subset of §10):
//   - Period phases are injected explicitly by the harness (ManualSwimPhases),
//     in a fixed node order, so periods are neither coalesced nor dropped.
//   - The injectable Fake clock supplies Now() for suspicion/reap deltas; it is
//     the only time source.
//   - All node timers that could fire on a clock Advance are disabled in sim
//     (keepalive off; the fallback-dial delay set far beyond any advance), so an
//     Advance never races a timer-woken goroutine into new work. The handshake
//     completes via immediate delivery during the no-loss connect phase, so its
//     retransmit timers never need to fire either.
//   - Quiescence is detected by a router activity barrier: after an action the
//     harness waits until no packet has been sent, dropped, or delivered for a
//     stable window AND no packet sits in any conn queue. Because every node
//     reaction either emits a router packet quickly or terminates, a stable
//     no-activity window means the mesh has fully reacted. This is -race clean
//     (mutex-guarded counters) and terminates.

// --- simConn / router ------------------------------------------------------

type simPkt struct {
	src  netip.AddrPort
	data []byte
}

type simConn struct {
	addr      netip.AddrPort
	r         *router
	queue     chan simPkt
	done      chan struct{}
	closeOnce sync.Once
}

func (c *simConn) WriteTo(b []byte, dst netip.AddrPort) error {
	cp := append([]byte(nil), b...)
	c.r.send(c.addr, dst, cp)
	return nil
}

func (c *simConn) ReadFrom(buf []byte) (int, netip.AddrPort, error) {
	select {
	case pkt := <-c.queue:
		// The delivery unit counted in router.send is NOT retired here: the
		// read loop relays the packet onward and the event loop retires the
		// unit after handleInbound. This conn is a transparent carrier.
		nn := copy(buf, pkt.data)
		return nn, pkt.src, nil
	case <-c.done:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

func (c *simConn) LocalAddr() netip.AddrPort { return c.addr }

func (c *simConn) Close() error {
	c.closeOnce.Do(func() { close(c.done) })
	return nil
}

type linkKey struct{ src, dst netip.AddrPort }

type router struct {
	mu           sync.Mutex
	conns        map[netip.AddrPort]*simConn
	rng          *rand.Rand
	lossPermille int
	dupPermille  int
	dupSent      int // count of injected on-wire duplicates (instrumentation)
	isolated     map[netip.AddrPort]bool
	blocked      map[linkKey]bool

	b *simBarrier
	t *testing.T
}

func newRouter(t *testing.T, seed int64, b *simBarrier) *router {
	return &router{
		conns:    make(map[netip.AddrPort]*simConn),
		rng:      rand.New(rand.NewSource(seed)),
		isolated: make(map[netip.AddrPort]bool),
		blocked:  make(map[linkKey]bool),
		b:        b,
		t:        t,
	}
}

func (r *router) register(addr netip.AddrPort) *simConn {
	c := &simConn{addr: addr, r: r, queue: make(chan simPkt, 4096), done: make(chan struct{})}
	r.mu.Lock()
	r.conns[addr] = c
	r.mu.Unlock()
	return c
}

// unregister drops a conn so sends to it are dropped rather than queued onto a
// conn whose read loop has exited (which would leave packets un-popped forever
// and prevent quiescence). Used when a node rebinds to a new address.
func (r *router) unregister(addr netip.AddrPort) {
	r.mu.Lock()
	delete(r.conns, addr)
	r.mu.Unlock()
}

func (r *router) send(src, dst netip.AddrPort, data []byte) {
	r.mu.Lock()
	drop := r.isolated[src] || r.isolated[dst] || r.blocked[linkKey{src, dst}]
	if !drop && r.lossPermille > 0 && r.rng.Intn(1000) < r.lossPermille {
		drop = true
	}
	dc := r.conns[dst]
	// Duplicate a fraction of the DELIVERED packets so the receiver sees genuine
	// on-wire duplicates (exercising the seq/offset dedup path), not only the
	// go-back-N retransmits loss produces. The RNG is drawn under the lock so the
	// sim stays bit-for-bit deterministic. Each copy is an independent delivery
	// unit, so the barrier stays balanced.
	copies := 1
	if !drop && dc != nil && r.dupPermille > 0 && r.rng.Intn(1000) < r.dupPermille {
		copies = 2
		r.dupSent++
	}
	if drop || dc == nil {
		r.mu.Unlock()
		return // dropped: no delivery unit created
	}
	r.mu.Unlock()
	// Count each delivery unit BEFORE the hand-off, so the consuming node's event
	// loop cannot retire it before it is counted. The unit is carried through
	// conn.queue -> read loop -> n.inbound and retired by the loop after
	// handleInbound.
	for i := 0; i < copies; i++ {
		r.b.add(1)
		select {
		case dc.queue <- simPkt{src: src, data: data}:
		default:
			r.b.done() // queue full: the packet is dropped, so retire its unit
		}
	}
}

// settle blocks until the mesh is fully quiescent via the happens-before
// barrier: every cross-goroutine work unit has been counted before its hand-off
// and retired only after the consuming handler (and all the work that handler
// spawned) completed, so a zero count is a race-free proof that no delivery,
// loop reaction, driver reaction, or piggybacked re-gossip is still pending. It
// is NOT a timing heuristic — the only sleeps are a watchdog that fails the
// test on a genuine deadlock, never a window the protocol must beat.
func (r *router) settle() {
	if !r.b.waitIdle(settleTimeout) {
		r.t.Fatalf("sim did not reach quiescence within %s (barrier busy=%d): "+
			"possible deadlock or an unbalanced sim-barrier hand-off", settleTimeout, r.b.load())
	}
}

const settleTimeout = 30 * time.Second

// simBarrier is the deterministic quiescence counter shared by every node and
// the router in one mesh. See the simHook contract in node.go: busy is
// incremented before a cross-goroutine hand-off and decremented after the
// consumer's handler returns, and because each child hand-off is counted inside
// its parent handler before that handler returns, busy only reaches zero at
// true quiescence.
type simBarrier struct {
	mu   sync.Mutex
	cond *sync.Cond
	busy int
}

func newSimBarrier() *simBarrier {
	b := &simBarrier{}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *simBarrier) add(k int) {
	b.mu.Lock()
	b.busy += k
	b.mu.Unlock()
}

func (b *simBarrier) done() {
	b.mu.Lock()
	b.busy--
	if b.busy <= 0 {
		b.busy = 0 // defensive: never negative
		b.cond.Broadcast()
	}
	b.mu.Unlock()
}

func (b *simBarrier) load() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.busy
}

// waitIdle blocks until busy == 0, returning false if timeout elapses first. A
// done() that reaches zero broadcasts immediately, so the common path is woken
// at once; a low-frequency ticker only exists so the waiter re-checks the
// deadline if a (bug-induced) deadlock means done() never fires. The ticker
// never gates correctness — quiescence is proven by busy == 0, not by elapsed
// time.
func (b *simBarrier) waitIdle(timeout time.Duration) bool {
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(10 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				b.cond.Broadcast()
			}
		}
	}()
	defer close(stop)

	deadline := time.Now().Add(timeout)
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.busy != 0 {
		if !time.Now().Before(deadline) {
			return false
		}
		b.cond.Wait()
	}
	return true
}

func (r *router) setLoss(permille int) {
	r.mu.Lock()
	r.lossPermille = permille
	r.mu.Unlock()
}

// setDup makes the router deliver a `permille`/1000 fraction of its delivered
// packets twice, injecting genuine on-wire duplicates.
func (r *router) setDup(permille int) {
	r.mu.Lock()
	r.dupPermille = permille
	r.mu.Unlock()
}

// dupSentCount returns how many on-wire duplicates the router has injected.
func (r *router) dupSentCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dupSent
}

func (r *router) isolate(addr netip.AddrPort, on bool) {
	r.mu.Lock()
	if on {
		r.isolated[addr] = true
	} else {
		delete(r.isolated, addr)
	}
	r.mu.Unlock()
}

func (r *router) blockLink(a, b netip.AddrPort, on bool) {
	r.mu.Lock()
	if on {
		r.blocked[linkKey{a, b}] = true
		r.blocked[linkKey{b, a}] = true
	} else {
		delete(r.blocked, linkKey{a, b})
		delete(r.blocked, linkKey{b, a})
	}
	r.mu.Unlock()
}

// --- mesh ------------------------------------------------------------------

type simNode struct {
	n       *Node
	id      *identity.Identity
	conn    *simConn
	disc    *discovery.Static
	addr    netip.AddrPort
	incPath string
}

type simMesh struct {
	t       *testing.T
	r       *router
	clk     *clock.Fake
	params  swim.Params
	psk     []byte
	nodes   []*simNode
	barrier *simBarrier
	seed    int64
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	seq     int
}

// idReader returns a deterministic key-material reader for the i-th node, so a
// mesh built with a given seed always produces the same node IDs.
func (m *simMesh) idReader(i int) io.Reader {
	return rand.New(rand.NewSource(m.seed*100_003 + int64(i)*31 + 17))
}

func testParams() swim.Params {
	p := swim.DefaultParams()
	p.T = 1 * time.Second
	p.TombstoneTTL = 60 * time.Second
	return p
}

func newSimMesh(t *testing.T, seed int64) *simMesh {
	ctx, cancel := context.WithCancel(context.Background())
	barrier := newSimBarrier()
	return &simMesh{
		t:       t,
		r:       newRouter(t, seed, barrier),
		clk:     clock.NewFake(time.Unix(1_700_000_000, 0)),
		params:  testParams(),
		psk:     mustPSK(t),
		barrier: barrier,
		seed:    seed,
		ctx:     ctx,
		cancel:  cancel,
	}
}

func (m *simMesh) addr(i int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}), 9000)
}

// addNode builds and starts a node with the given options and returns it.
func (m *simMesh) addNode(t *testing.T, label string, opts func(cfg *Config)) *simNode {
	i := len(m.nodes)
	addr := m.addr(i)
	// Deterministic identity: seed the key material from the mesh seed and node
	// index so a given mesh has reproducible node IDs across runs. Everything
	// that keys off the node ID (roster order, probe round-robin, initiator
	// election) is then run-independent.
	id, err := identity.GenerateFrom(label, m.idReader(i))
	if err != nil {
		t.Fatal(err)
	}
	conn := m.r.register(addr)
	disc := discovery.NewStatic()
	rng := rand.New(rand.NewSource(int64(1000 + i)))
	incPath := fmt.Sprintf("%s/inc-%d", t.TempDir(), i)
	cfg := Config{
		Identity:          id,
		NetworkPSK:        m.psk,
		Policy:            transport.AllowList(nil, false),
		Discovery:         disc,
		Conn:              conn,
		Clock:             m.clk,
		SwimParams:        m.params,
		IncarnationPath:   incPath,
		SelfEndpoint:      addr,
		SwimRand:          rng,
		ManualSwimPhases:  true,
		DisableKeepalive:  true,
		FallbackDialDelay: 24 * time.Hour,
	}
	if opts != nil {
		opts(&cfg)
	}
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	n.sim = m.barrier // deterministic quiescence barrier (set before Run starts)
	sn := &simNode{n: n, id: id, conn: conn, disc: disc, addr: addr, incPath: incPath}
	m.nodes = append(m.nodes, sn)
	m.wg.Add(1)
	go func() { defer m.wg.Done(); _ = n.Run(m.ctx) }()
	return sn
}

// restartNode tears a node down and brings it back up with the SAME identity
// and incarnation-persistence path (exercising the incarnation-reset subtlety).
func (m *simMesh) restartNode(sn *simNode) *simNode {
	// Build a brand-new conn at the same address (the old one is closed when its
	// node's Run returns after we cancel its ctx via mesh teardown — but we only
	// restart individual nodes here, so close the old conn explicitly).
	oldAddr := sn.addr
	sn.conn.Close()
	m.r.unregister(oldAddr)
	i := indexOf(m.nodes, sn)
	// A restarted node typically rebinds a fresh ephemeral endpoint. Using a new
	// address exercises the identity-not-address path (the roster is keyed by
	// node ID) and avoids colliding with any stale session peers still hold at
	// the old address. Identity + incarnation-persistence path are unchanged —
	// that is what exercises the incarnation-reset subtlety.
	addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 2, byte(i + 1)}), 9000)
	sn.addr = addr
	conn := m.r.register(addr)
	rng := rand.New(rand.NewSource(int64(2000 + i)))
	cfg := Config{
		Identity:          sn.id,
		NetworkPSK:        m.psk,
		Policy:            transport.AllowList(nil, false),
		Discovery:         sn.disc,
		Conn:              conn,
		Clock:             m.clk,
		SwimParams:        m.params,
		IncarnationPath:   sn.incPath,
		SelfEndpoint:      addr,
		SwimRand:          rng,
		ManualSwimPhases:  true,
		DisableKeepalive:  true,
		FallbackDialDelay: 24 * time.Hour,
	}
	n, err := New(cfg)
	if err != nil {
		m.t.Fatal(err)
	}
	n.sim = m.barrier
	sn.n = n
	sn.conn = conn
	m.wg.Add(1)
	go func() { defer m.wg.Done(); _ = n.Run(m.ctx) }()
	return sn
}

func indexOf(ns []*simNode, sn *simNode) int {
	for i, x := range ns {
		if x == sn {
			return i
		}
	}
	return -1
}

// wireFullMesh seeds every node's discovery with hints for every other node.
func (m *simMesh) wireFullMesh() {
	for _, a := range m.nodes {
		for _, b := range m.nodes {
			if a == b {
				continue
			}
			a.disc.Push(discovery.PeerHint{
				NodeID:       b.id.NodeID().String(),
				Addrs:        []netip.AddrPort{b.addr},
				ProtoVersion: discovery.ProtoVersion,
			})
		}
	}
}

// hint seeds node a's discovery with a hint for node b.
func (m *simMesh) hint(a, b *simNode) {
	a.disc.Push(discovery.PeerHint{
		NodeID:       b.id.NodeID().String(),
		Addrs:        []netip.AddrPort{b.addr},
		ProtoVersion: discovery.ProtoVersion,
	})
}

// period runs one synchronized protocol period: advance the clock by T, then
// inject phases 0,1,2 across the mesh. Within each phase every node is driven in
// a FIXED order and the mesh is settled to full quiescence after EACH node, not
// after the whole phase. Combined with the happens-before barrier and the
// per-node seeded RNGs, this gives a single, total, run-independent order of
// operations — so gossip timing and convergence are bit-for-bit deterministic
// rather than dependent on goroutine scheduling. (Each settle still runs every
// node's loop/driver/read goroutines concurrently, so -race coverage of the
// cross-goroutine peer-table/session access is unchanged.)
func (m *simMesh) period() {
	m.clk.Advance(m.params.T)
	m.r.settle()
	for _, phase := range []int{0, 1, 2} {
		for _, sn := range m.nodes {
			sn.n.InjectPhase(m.ctx, phase)
			m.r.settle()
		}
	}
}

// periods runs k periods.
func (m *simMesh) periods(k int) {
	for i := 0; i < k; i++ {
		m.period()
	}
}

// advance moves the clock without running phases (used to cross a suspicion or
// reap threshold between explicit periods).
func (m *simMesh) advance(d time.Duration) {
	m.clk.Advance(d)
	m.r.settle()
}

func (m *simMesh) stop() {
	m.cancel()
	done := make(chan struct{})
	go func() { m.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		m.t.Fatal("mesh did not shut down within 10s (goroutine leak?)")
	}
}

// waitAllConnected polls until every node is connected to every other node (or
// times out). Connection uses the node goroutines + immediate delivery, so a
// poll (not the activity barrier) is the right tool here.
func (m *simMesh) waitAllConnected(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m.r.settle()
		if m.allConnected() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return m.allConnected()
}

func (m *simMesh) allConnected() bool {
	for _, a := range m.nodes {
		got := map[identity.NodeID]bool{}
		for _, p := range a.n.Snapshot() {
			if p.State == StateConnected && p.HasID {
				got[p.NodeID] = true
			}
		}
		for _, b := range m.nodes {
			if a == b {
				continue
			}
			if !got[b.id.NodeID()] {
				return false
			}
		}
		// Require every peer to be PROBEABLE (session published by
		// handleSessReady), not merely StateConnected (set earlier in
		// handleAuth). The gap between the two is an uncounted driver transition,
		// so without this the first failure-detector period could run with a
		// partial probeable set — making probe-target RNG consumption, and hence
		// the whole deterministic probe sequence, vary run-to-run.
		if a.n.probeablePeerCountForTest() < len(m.nodes)-1 {
			return false
		}
	}
	return true
}

// --- assertion helpers -----------------------------------------------------

func (m *simMesh) stateOf(observer, subject *simNode) (string, bool) {
	return observer.n.MemberState(subject.id.NodeID())
}

func (m *simMesh) incOf(observer, subject *simNode) (uint64, bool) {
	return observer.n.MemberIncarnation(subject.id.NodeID())
}

// goroutineCount returns the current goroutine count after a short settle, for
// the leak check.
func goroutineCount() int {
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	return runtime.NumGoroutine()
}

// --- test-only update injection + helpers ----------------------------------

func idFake(b byte) identity.NodeID {
	var n identity.NodeID
	n[0] = 0xF0
	n[1] = b
	n[31] = b
	return n
}

func swimAlive(id identity.NodeID, inc uint64) swim.Update {
	return swim.Update{NodeID: id, Incarnation: inc, State: swim.StateAlive}
}

func swimAliveEP(id identity.NodeID, inc uint64, ep netip.AddrPort) swim.Update {
	return swim.Update{NodeID: id, Incarnation: inc, State: swim.StateAlive, Endpoint: ep}
}

// injectUpdate applies an update to a node's roster and seeds it into the gossip
// buffer, as if it had arrived on a frame. It reaches into the loop-owned state
// directly; the mesh is quiesced around test calls, so there is no concurrent
// loop access. (It still takes n.mu to satisfy the race detector against the
// renderer.)
func injectUpdate(sn *simNode, u swim.Update, now time.Time) {
	n := sn.n
	n.mu.Lock()
	res := n.roster.Apply(u, now)
	sends := n.params.RetransmitCount(n.roster.Size())
	n.mu.Unlock()
	if res.Regossip != nil {
		n.gossip.Add(*res.Regossip, sends)
	}
}

// sessionUp reports whether observer holds a live connected session to subject.
func sessionUp(observer, subject *simNode) bool {
	for _, p := range observer.n.Snapshot() {
		if p.State == StateConnected && p.HasID && p.NodeID == subject.id.NodeID() {
			return true
		}
	}
	return false
}

// applyMutualAllowList sets each node's trust policy to trust exactly the other
// nodes in the set (called before the mesh connects).
func applyMutualAllowList(nodes []*simNode) {
	for _, a := range nodes {
		trusted := map[identity.NodeID]struct{}{}
		for _, b := range nodes {
			if a == b {
				continue
			}
			trusted[b.id.NodeID()] = struct{}{}
		}
		policy := transport.AllowList(trusted, true)
		a.n.setPolicyForTest(policy)
	}
}

// setPolicyForTest swaps the trust policy and the roster allow-list gate
// race-safely (used before the mesh connects).
func (n *Node) setPolicyForTest(policy transport.TrustPolicy) {
	n.mu.Lock()
	n.policy = policy
	n.enforce = true
	n.roster.SetAllowed(func(id identity.NodeID) bool { return policy(id) == transport.TrustAccept })
	n.mu.Unlock()
}

// resetGossipForTest empties this node's gossip buffer. It is only safe when the
// mesh is quiesced (the loop goroutine is parked and settle() has established a
// happens-before edge via the barrier mutex), which is exactly when the harness
// calls it — the same quiescence contract injectUpdate relies on.
func (n *Node) resetGossipForTest() { n.gossip.Reset() }

// probeablePeerCountForTest returns how many peers currently have a live
// authenticated session (are SWIM-probeable), under the renderer mutex.
func (n *Node) probeablePeerCountForTest() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.probeableIDsLocked())
}

// memberCountForTest returns the number of non-self roster members.
func (n *Node) memberCountForTest() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.roster.MemberCount()
}

// halfOpenLenForTest returns the current half-open table size.
func (n *Node) halfOpenLenForTest() int { return n.half.Len() }

// --- v0.3 session sim helpers ----------------------------------------------

// dropTransport blocks the link both ways (a silent blackhole), as a WiFi-off /
// mid-stream transport drop. The Noise session objects stay alive on both sides
// (no read deadline), so this exercises the same-epoch pause/retransmit path.
func (m *simMesh) dropTransport(a, b *simNode) { m.r.blockLink(a.addr, b.addr, true) }

// healTransport unblocks a dropped link.
func (m *simMesh) healTransport(a, b *simNode) { m.r.blockLink(a.addr, b.addr, false) }

// rebindConn simulates a roam: the node keeps its *Node AND its entire session
// registry, but its UDP socket moves to a new address. The old conn is closed
// (its read loop exits), discovery is re-seeded so peers re-handshake to the new
// address, and sn.addr is updated. Unlike restartNode (a fresh *Node with empty
// session memory — the SWIM-dead case), this preserves durable sessions, which
// is exactly the roam-resume path.
func (m *simMesh) rebindConn(sn *simNode, newAddr netip.AddrPort) {
	old := sn.addr
	conn := m.r.register(newAddr)
	sn.n.RebindConnForTest(conn)
	m.r.unregister(old)
	sn.conn = conn
	sn.addr = newAddr
}

// sessTickAll injects one session tick into every node, settling after each so
// each tick's full cascade (seals, deliveries, teardown, re-dial) completes
// before the next node ticks — the same total-order discipline as period().
func (m *simMesh) sessTickAll() {
	for _, sn := range m.nodes {
		sn.n.InjectSessionTick(m.ctx)
		m.r.settle()
	}
}

// sessPump advances the clock by d and injects a session tick round, k times.
func (m *simMesh) sessPump(d time.Duration, k int) {
	for i := 0; i < k; i++ {
		m.clk.Advance(d)
		m.r.settle()
		m.sessTickAll()
	}
}
