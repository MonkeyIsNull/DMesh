// Package node ties identity, discovery, and the Noise transport into a running
// DMesh node with a single-owner concurrency model.
//
// Exactly one event-loop goroutine owns the peer table (byAddr/byID). Every
// other goroutine - the UDP read loop, discovery browse, each peer's
// handshake/session driver, per-peer keep-alive timers, and the status renderer
// - talks to the loop by channel; the renderer reads a snapshot through the
// same mutex the loop writes under. Each peer's two Noise CipherStates live in
// one transport.Session whose send path is internally serialized by a single
// atomic nonce, so no CipherState is ever touched by two goroutines.
package node

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"net/netip"
	"sync"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/clock"
	"github.com/MonkeyIsNull/DMesh/internal/discovery"
	"github.com/MonkeyIsNull/DMesh/internal/identity"
	"github.com/MonkeyIsNull/DMesh/internal/swim"
	"github.com/MonkeyIsNull/DMesh/internal/transport"
)

const (
	defaultKeepaliveInterval = 5 * time.Second
	defaultFallbackDialDelay = 1 * time.Second
	halfOpenLimit            = 256
)

// Config configures a Node.
type Config struct {
	Identity   *identity.Identity
	NetworkPSK []byte
	Policy     transport.TrustPolicy
	Discovery  discovery.Discovery
	Conn       transport.PacketConn
	Clock      clock.Clock
	// EnforceAllowList is surfaced in the status view.
	EnforceAllowList bool
	// SendGreeting, if set, makes the initiator send a text ping after connect.
	SendGreeting bool

	// --- v0.2 SWIM membership ---

	// SwimParams overrides the SWIM tunables; the zero value uses
	// swim.DefaultParams().
	SwimParams swim.Params
	// IncarnationPath is where this node's self incarnation is persisted
	// (beside the identity). A NON-EMPTY path is required for the restart
	// split-brain guarantee: it is what lets a restarted node resume at
	// persisted+1 and so out-rank any stale Suspect/Dead the mesh still holds
	// about it (and lets the handshake-join-sync ground-truth path deliver a
	// legitimate high-incarnation self-update without MaxSelfIncJump rejecting
	// it as forged). An EMPTY path forfeits that safety — the incarnation resets
	// to 1 on every start, so the documented asymmetric-reap split-brain can
	// recur — and is intended ONLY for ephemeral or test nodes. The production
	// CLI always wires a real path.
	IncarnationPath string
	// SelfEndpoint is the dial hint this node advertises for itself in gossip.
	// Zero uses the bound local address.
	SelfEndpoint netip.AddrPort
	// SwimRand injects the shuffle RNG for deterministic tests. Nil seeds from
	// the wall clock.
	SwimRand *mrand.Rand

	// --- test seams (all default to production behaviour) ---

	// ManualSwimPhases disables the internal phase-timer goroutine; the test
	// harness injects period phases on InjectPhase instead.
	ManualSwimPhases bool
	// DisableKeepalive turns off the per-peer keepalive (tests drive liveness
	// purely through SWIM probes).
	DisableKeepalive bool
	// FallbackDialDelay overrides the discovery fallback-dial delay (0 = default).
	FallbackDialDelay time.Duration
	// DisableJoinSync suppresses the bidirectional join-sync burst on connect
	// (used to isolate pure gossip convergence).
	DisableJoinSync bool
	// DisableGossipDial suppresses feeding gossip-learned endpoints back into
	// discovery (used to isolate pure gossip convergence).
	DisableGossipDial bool
}

// Node is a running DMesh node.
type Node struct {
	self     *identity.Identity
	psk      []byte
	policy   transport.TrustPolicy
	disc     discovery.Discovery
	conn     transport.PacketConn
	clk      clock.Clock
	enforce  bool
	greeting bool

	mu     sync.RWMutex
	byAddr map[netip.AddrPort]*peer
	byID   map[identity.NodeID]*peer
	half   *transport.HalfOpenTable

	inbound   chan inPkt
	hints     chan discovery.PeerHint
	auth      chan *authReq
	lastSeen  chan lsUpdate
	done      chan netip.AddrPort
	forceDial chan forceDialReq

	// --- v0.2 SWIM state, owned exclusively by the loop goroutine ---
	roster       *swim.Roster
	gossip       *swim.Buffer
	detector     *swim.Detector
	params       swim.Params
	rng          *mrand.Rand
	swimSeq      uint32
	relayPending map[uint32]relayReq

	incPath           string
	selfEndpoint      netip.AddrPort
	manualPhases      bool
	disableKeepalive  bool
	keepaliveInterval time.Duration
	fallbackDelay     time.Duration
	disableJoinSync   bool
	disableGossipDial bool

	sessReady chan sessReadyMsg
	swimIn    chan swimInbound
	swimPhase chan int
	leaveCh   chan chan struct{}

	// sim is the deterministic-test happens-before barrier. It is nil in
	// production (every call is a cheap nil-guarded no-op) and set by the
	// in-memory sim harness before Run starts. See simHook.
	sim simHook

	wg sync.WaitGroup
}

// simHook is the test-only quiescence barrier interface implemented by the sim
// harness (sim_test.go). It gives the harness a true happens-before barrier
// instead of a wall-clock sleep: a work unit is counted (add) BEFORE it is
// handed off to another goroutine, and uncounted (done) AFTER the consuming
// handler has fully returned — having already counted any downstream work it
// generated. Because every child hand-off is counted inside its parent handler
// before that handler returns, the counter never dips to zero mid-cascade, so
// "counter == 0" is a sound, race-free proof that the mesh is fully quiescent.
type simHook interface {
	add(int)
	done()
}

// sbAdd counts one outstanding cross-goroutine work unit (no-op in production).
func (n *Node) sbAdd() {
	if n.sim != nil {
		n.sim.add(1)
	}
}

// sbDone retires one work unit counted by sbAdd (no-op in production).
func (n *Node) sbDone() {
	if n.sim != nil {
		n.sim.done()
	}
}

// relayReq tracks an outstanding indirect probe this node is relaying on behalf
// of a requester: the requester's ping-req seq is answered once the target acks
// our relay ping (keyed by the fresh seq we used to ping the target).
type relayReq struct {
	requester identity.NodeID
	reqSeq    uint32
	target    identity.NodeID
	deadline  time.Time
}

type sessReadyMsg struct {
	addr netip.AddrPort
	sess *transport.Session
}

type swimInbound struct {
	fromID   identity.NodeID
	fromAddr netip.AddrPort
	body     []byte
}

type inPkt struct {
	addr netip.AddrPort
	data []byte
}

type authReq struct {
	addr  netip.AddrPort
	res   *transport.HandshakeResult
	reply chan bool
}

type lsUpdate struct {
	addr     netip.AddrPort
	at       time.Time
	label    string
	hasLabel bool
}

type forceDialReq struct {
	addr   netip.AddrPort
	nodeID identity.NodeID
	label  string
}

// New builds a Node from a Config.
func New(cfg Config) (*Node, error) {
	if err := transport.ValidatePSK(cfg.NetworkPSK); err != nil {
		return nil, err
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.Real{}
	}
	if cfg.Policy == nil {
		cfg.Policy = transport.AllowList(nil, false)
	}

	params := cfg.SwimParams
	if params.T == 0 {
		params = swim.DefaultParams()
	}
	selfEndpoint := cfg.SelfEndpoint
	if !selfEndpoint.IsValid() {
		selfEndpoint = cfg.Conn.LocalAddr()
	}
	rng := cfg.SwimRand
	if rng == nil {
		rng = mrand.New(mrand.NewSource(time.Now().UnixNano()))
	}
	keepalive := defaultKeepaliveInterval
	fallback := cfg.FallbackDialDelay
	if fallback == 0 {
		fallback = defaultFallbackDialDelay
	}

	// Resume the self incarnation at persisted+1. A held identity implies a held
	// incarnation that strictly exceeds any stale membership the mesh carries
	// about us, so our post-(re)start Alive always wins.
	selfInc := uint64(1)
	if cfg.IncarnationPath != "" {
		selfInc = swim.LoadIncarnation(cfg.IncarnationPath) + 1
		_ = swim.SaveIncarnation(cfg.IncarnationPath, selfInc)
	}

	n := &Node{
		self:              cfg.Identity,
		psk:               cfg.NetworkPSK,
		policy:            cfg.Policy,
		disc:              cfg.Discovery,
		conn:              cfg.Conn,
		clk:               cfg.Clock,
		enforce:           cfg.EnforceAllowList,
		greeting:          cfg.SendGreeting,
		byAddr:            make(map[netip.AddrPort]*peer),
		byID:              make(map[identity.NodeID]*peer),
		half:              transport.NewHalfOpenTable(halfOpenLimit),
		inbound:           make(chan inPkt, 256),
		hints:             make(chan discovery.PeerHint, 64),
		auth:              make(chan *authReq, 16),
		lastSeen:          make(chan lsUpdate, 256),
		done:              make(chan netip.AddrPort, 64),
		forceDial:         make(chan forceDialReq, 64),
		params:            params,
		gossip:            swim.NewBuffer(gossipBufferCap(params)),
		detector:          swim.NewDetector(),
		rng:               rng,
		relayPending:      make(map[uint32]relayReq),
		incPath:           cfg.IncarnationPath,
		selfEndpoint:      selfEndpoint,
		manualPhases:      cfg.ManualSwimPhases,
		disableKeepalive:  cfg.DisableKeepalive,
		keepaliveInterval: keepalive,
		fallbackDelay:     fallback,
		disableJoinSync:   cfg.DisableJoinSync,
		disableGossipDial: cfg.DisableGossipDial,
		sessReady:         make(chan sessReadyMsg, 64),
		swimIn:            make(chan swimInbound, 256),
		swimPhase:         make(chan int, 8),
		leaveCh:           make(chan chan struct{}, 1),
	}

	var persist func(uint64) error
	if cfg.IncarnationPath != "" {
		persist = func(v uint64) error { return swim.SaveIncarnation(cfg.IncarnationPath, v) }
	}
	var allowed func(identity.NodeID) bool
	if cfg.EnforceAllowList {
		// Gate gossip-learned members by the same authenticated allow-list the
		// handshake enforces, so a credentialed peer cannot inject a fabricated
		// member or amplify one.
		allowed = func(id identity.NodeID) bool {
			return cfg.Policy(id) == transport.TrustAccept
		}
	}
	n.roster = swim.NewRoster(swim.RosterConfig{
		Self:         cfg.Identity.NodeID(),
		SelfInc:      selfInc,
		SelfEndpoint: selfEndpoint,
		Params:       params,
		Persist:      persist,
		Allowed:      allowed,
	})
	// Seed our own Alive so peers learn our (possibly post-restart) incarnation.
	n.gossip.Add(n.roster.SelfAlive(), params.RetransmitCount(1))
	return n, nil
}

// gossipBufferCap bounds the gossip buffer to O(N) with a small absolute
// ceiling so churn cannot grow it without bound.
func gossipBufferCap(p swim.Params) int {
	const absoluteCeiling = 4096
	return absoluteCeiling
}

// SelfID returns this node's ID.
func (n *Node) SelfID() identity.NodeID { return n.self.NodeID() }

// SelfLabel returns this node's label.
func (n *Node) SelfLabel() string { return n.self.Label }

// LocalAddr returns the bound UDP endpoint.
func (n *Node) LocalAddr() netip.AddrPort { return n.conn.LocalAddr() }

// EnforceAllowList reports whether the allow-list is enforced.
func (n *Node) EnforceAllowList() bool { return n.enforce }

// Run starts the node and blocks until ctx is canceled.
func (n *Node) Run(ctx context.Context) error {
	// UDP read loop.
	n.wg.Add(1)
	go n.readLoop(ctx)

	// Discovery.
	if n.disc != nil {
		self := discovery.Self{
			NodeID:       n.self.NodeID().String(),
			Label:        n.self.Label,
			Port:         int(n.conn.LocalAddr().Port()),
			ProtoVersion: discovery.ProtoVersion,
		}
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			_ = n.disc.Advertise(ctx, self)
		}()
		ch, err := n.disc.Browse(ctx)
		if err != nil {
			return fmt.Errorf("node: browse: %w", err)
		}
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case h, ok := <-ch:
					if !ok {
						return
					}
					n.sbAdd()
					select {
					case n.hints <- h:
					case <-ctx.Done():
						n.sbDone()
						return
					}
				}
			}
		}()
	}

	// SWIM protocol-period phase driver (production only; tests inject phases).
	if !n.manualPhases {
		n.wg.Add(1)
		go n.runPhases(ctx)
	}

	n.loop(ctx)
	// Unblock readLoop, which is parked in a blocking ReadFrom, so Run can
	// return once ctx is canceled. A second Close by the caller is harmless.
	_ = n.conn.Close()
	n.wg.Wait()
	return nil
}

// runPhases fires the three SWIM period phases (t=0, t=T/3, t=T) on the
// injectable clock. It is the only new long-lived goroutine, and it only
// signals the loop; all SWIM work happens in the loop.
func (n *Node) runPhases(ctx context.Context) {
	defer n.wg.Done()
	third := n.params.T / 3
	rest := n.params.T - third
	for {
		if !n.sendPhase(ctx, 0) {
			return
		}
		if !n.sleep(ctx, third) {
			return
		}
		if !n.sendPhase(ctx, 1) {
			return
		}
		if !n.sleep(ctx, rest) {
			return
		}
		if !n.sendPhase(ctx, 2) {
			return
		}
	}
}

func (n *Node) sendPhase(ctx context.Context, phase int) bool {
	n.sbAdd()
	select {
	case n.swimPhase <- phase:
		return true
	case <-ctx.Done():
		n.sbDone()
		return false
	}
}

func (n *Node) sleep(ctx context.Context, d time.Duration) bool {
	t := n.clk.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C():
		return true
	case <-ctx.Done():
		return false
	}
}

// InjectPhase delivers a period phase (0, 1, or 2) to the loop. It is used by
// the deterministic test harness in place of the phase-timer goroutine. The
// phase is counted so the harness's settle() blocks until the loop has fully
// processed it and every cascading reaction it triggers.
func (n *Node) InjectPhase(ctx context.Context, phase int) {
	n.sbAdd()
	select {
	case n.swimPhase <- phase:
	case <-ctx.Done():
		n.sbDone()
	}
}

// Leave announces a graceful departure (Left update flushed to peers) and
// blocks until the loop has processed it or ctx is canceled.
func (n *Node) Leave(ctx context.Context) {
	reply := make(chan struct{})
	n.sbAdd()
	select {
	case n.leaveCh <- reply:
	case <-ctx.Done():
		n.sbDone()
		return
	}
	select {
	case <-reply:
	case <-ctx.Done():
	}
}

// loop is the single event loop that owns the peer table.
func (n *Node) loop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pk := <-n.inbound:
			n.handleInbound(ctx, pk)
			n.sbDone()
		case h := <-n.hints:
			n.handleHint(ctx, h)
			n.sbDone()
		case a := <-n.auth:
			n.handleAuth(a)
			n.sbDone()
		case u := <-n.lastSeen:
			n.handleLastSeen(u)
			n.sbDone()
		case addr := <-n.done:
			n.handleDone(addr)
			n.sbDone()
		case fd := <-n.forceDial:
			n.handleForceDial(ctx, fd)
			n.sbDone()
		case sr := <-n.sessReady:
			n.handleSessReady(sr)
			n.sbDone()
		case in := <-n.swimIn:
			n.handleSwimIn(in)
			n.sbDone()
		case phase := <-n.swimPhase:
			n.handlePhase(phase)
			n.sbDone()
		case reply := <-n.leaveCh:
			n.handleLeave()
			close(reply)
			n.sbDone()
		}
	}
}

func (n *Node) readLoop(ctx context.Context) {
	defer n.wg.Done()
	buf := make([]byte, transport.MaxFrame)
	for {
		nb, addr, err := n.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		data := make([]byte, nb)
		copy(data, buf[:nb])
		// Each packet read here was counted once by the sim router when it was
		// enqueued; this loop just relays it (the event loop retires the unit
		// after handleInbound). On shutdown the relay is abandoned, so retire the
		// carried unit here to keep the barrier balanced.
		select {
		case n.inbound <- inPkt{addr: canonAddr(addr), data: data}:
		case <-ctx.Done():
			n.sbDone()
			return
		}
	}
}

func (n *Node) handleInbound(ctx context.Context, pk inPkt) {
	if p := n.byAddr[pk.addr]; p != nil && p.inbox != nil {
		// Count the loop->driver hand-off only once the peer is Connected: then
		// runSession is the inbox consumer and retires each unit. During the
		// handshake the inbox is drained by the transport state machine instead,
		// which cannot retire units, so those frames are left uncounted (the
		// handshake phase is covered by the harness's connection poll, not the
		// barrier).
		if p.state == StateConnected {
			n.sbAdd()
			select {
			case p.inbox <- pk.data:
			default: // peer's inbox is full; drop (UDP semantics)
				n.sbDone()
			}
			return
		}
		select {
		case p.inbox <- pk.data:
		default:
		}
		return
	}
	// Unknown source: only an opening handshake (msg1) starts a responder.
	if idx, ok := transport.PeekHandshake(pk.data); ok && idx == 1 {
		p := n.startResponder(ctx, pk.addr)
		select {
		case p.inbox <- pk.data:
		default:
		}
	}
}

func (n *Node) handleHint(ctx context.Context, h discovery.PeerHint) {
	nid, err := identity.ParseNodeID(h.NodeID)
	if err != nil {
		return
	}
	if nid == n.self.NodeID() {
		return // self-filter: zeroconf echoes our own advertisement
	}
	if len(h.Addrs) == 0 {
		return
	}
	addr := canonAddr(h.Addrs[0])

	if ex := n.byID[nid]; ex != nil && ex.state == StateConnected {
		// Already connected AND the roster still regards the peer as alive:
		// nothing to do. But if the roster considers it not-alive (Suspect/Dead,
		// e.g. after a restart that rebound a new address), the existing session
		// is stale — allow a fresh dial to the new endpoint, which the
		// handshake-as-ground-truth path in handleAuth will accept in its place.
		if st, ok := n.roster.State(nid); !ok || st == swim.StateAlive {
			return
		}
	}
	if n.byAddr[addr] != nil {
		return // already handshaking/connected/discovered with this endpoint
	}

	// Deterministic initiator election: the lexicographically smaller node ID
	// dials; the larger waits and only responds, with a fallback dial timer to
	// cover handshake loss or a spoofed TXT.
	if n.self.NodeID().String() < nid.String() {
		n.startInitiator(ctx, addr, nid, h.Label)
		return
	}
	n.addDiscovered(addr, nid, h.Label)
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		t := n.clk.NewTimer(n.fallbackDelay)
		defer t.Stop()
		select {
		case <-ctx.Done():
		case <-t.C():
			n.sbAdd()
			select {
			case n.forceDial <- forceDialReq{addr: addr, nodeID: nid, label: h.Label}:
			case <-ctx.Done():
				n.sbDone()
			}
		}
	}()
}

func (n *Node) handleForceDial(ctx context.Context, fd forceDialReq) {
	p := n.byAddr[fd.addr]
	if p == nil {
		n.startInitiator(ctx, fd.addr, fd.nodeID, fd.label)
		return
	}
	if p.state == StateDiscovered {
		n.upgradeToInitiator(ctx, p)
	}
}

// sendAuthReply answers a driver's auth request, counting the loop->driver
// hand-off so the deterministic barrier waits for the driver to observe it. The
// reply channel is buffered (cap 1) and single-use, so the send never blocks.
func (n *Node) sendAuthReply(a *authReq, ok bool) {
	n.sbAdd()
	a.reply <- ok
}

func (n *Node) handleAuth(a *authReq) {
	n.mu.Lock()
	defer n.mu.Unlock()
	p := n.byAddr[a.addr]
	if p == nil {
		n.sendAuthReply(a, false)
		return
	}
	if n.policy(a.res.PeerNodeID) == transport.TrustReject {
		p.state = StateFailed
		n.sendAuthReply(a, false)
		return
	}
	// Identity-keyed collapse: if a connected session already exists for this
	// authenticated node ID, normally drop the newer one (keep exactly one
	// stable session per peer identity).
	//
	// Exception — handshake-as-ground-truth (v0.2): if the roster regards the
	// existing session's peer as NOT alive (Suspect/Dead), a freshly-completed
	// authenticated handshake is proof the peer is back (e.g. a restart, often
	// from a new address). Replace the stale session rather than reject the new
	// one, which would otherwise be blocked forever by a session the mesh has
	// already given up on. A node cannot forge a completed Noise handshake, so
	// this is sound ground truth.
	if ex := n.byID[a.res.PeerNodeID]; ex != nil && ex != p && ex.state == StateConnected {
		st, known := n.roster.State(a.res.PeerNodeID)
		staleExisting := known && st != swim.StateAlive
		if !staleExisting {
			n.sendAuthReply(a, false)
			return
		}
		if ex.cancel != nil {
			ex.cancel() // tear down the stale session; handleDone will clean its address keys
		}
	}
	p.nodeID = a.res.PeerNodeID
	p.state = StateConnected
	p.lastSeen = n.clk.Now()
	n.byID[a.res.PeerNodeID] = p
	// The handshake is complete: drop the half-open entry so the table bounds
	// only genuinely in-progress handshakes. Leaving connected peers in it would
	// let a valid-PSK handshake flood evict (and cancel) live sessions once the
	// table filled - the opposite of what the half-open bound is for.
	n.half.Remove(a.addr)
	n.sendAuthReply(a, true)
}

func (n *Node) handleLastSeen(u lsUpdate) {
	n.mu.Lock()
	defer n.mu.Unlock()
	p := n.byAddr[u.addr]
	if p == nil {
		return
	}
	p.lastSeen = u.at
	if u.hasLabel && u.label != "" {
		p.label = u.label
	}
	// Any decrypted frame from a connected peer is liveness for probe
	// bookkeeping ONLY: it suppresses this node's current-period suspicion of
	// the sender. It never rewrites roster incarnation/state (that is reserved
	// for the subject's own incarnation-bearing Alive refutation).
	if !p.nodeID.IsZero() {
		n.detector.AckFrom(p.nodeID)
	}
}

func (n *Node) handleDone(addr netip.AddrPort) {
	n.mu.Lock()
	defer n.mu.Unlock()
	p := n.byAddr[addr]
	if p == nil {
		return
	}
	// Only remove if this peer never reached a stable connected identity, or
	// drop both keys otherwise.
	if !p.nodeID.IsZero() {
		if n.byID[p.nodeID] == p {
			delete(n.byID, p.nodeID)
		}
	}
	delete(n.byAddr, addr)
	n.half.Remove(addr)
}

// --- peer creation ----------------------------------------------------------

func (n *Node) addDiscovered(addr netip.AddrPort, nid identity.NodeID, label string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.byAddr[addr] != nil {
		return
	}
	n.byAddr[addr] = &peer{
		addr:     addr,
		nodeID:   nid,
		label:    label,
		state:    StateDiscovered,
		lastSeen: n.clk.Now(),
	}
}

func (n *Node) startInitiator(ctx context.Context, addr netip.AddrPort, nid identity.NodeID, label string) {
	n.mu.Lock()
	p := n.byAddr[addr]
	if p == nil {
		p = &peer{addr: addr}
		n.byAddr[addr] = p
	}
	p.inbox = make(chan []byte, 64)
	p.initiator = true
	p.nodeID = nid
	p.label = label
	p.state = StateHandshaking
	p.localIndex = randIndex()
	pctx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	n.admitHalfOpen(addr)
	n.mu.Unlock()

	n.wg.Add(1)
	go n.driveInitiator(pctx, p)
}

func (n *Node) upgradeToInitiator(ctx context.Context, p *peer) {
	n.mu.Lock()
	p.inbox = make(chan []byte, 64)
	p.initiator = true
	p.state = StateHandshaking
	p.localIndex = randIndex()
	pctx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	n.admitHalfOpen(p.addr)
	n.mu.Unlock()

	n.wg.Add(1)
	go n.driveInitiator(pctx, p)
}

// admitHalfOpen bounds in-progress handshakes, canceling the oldest if the
// table is full. The caller holds n.mu.
func (n *Node) admitHalfOpen(addr netip.AddrPort) {
	if evicted, did := n.half.Admit(addr); did {
		if ep := n.byAddr[evicted]; ep != nil && ep.cancel != nil {
			ep.cancel()
		}
	}
}

func (n *Node) startResponder(ctx context.Context, addr netip.AddrPort) *peer {
	n.mu.Lock()
	p := &peer{
		addr:       addr,
		inbox:      make(chan []byte, 64),
		state:      StateHandshaking,
		localIndex: randIndex(),
	}
	pctx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	n.byAddr[addr] = p
	n.admitHalfOpen(addr)
	n.mu.Unlock()

	n.wg.Add(1)
	go n.driveResponder(pctx, p)
	return p
}

// --- drivers ----------------------------------------------------------------

func (n *Node) driveInitiator(ctx context.Context, p *peer) {
	defer n.wg.Done()
	defer n.notifyDone(ctx, p.addr)
	snd := transport.AddrSender{Conn: n.conn, Addr: p.addr}
	res, err := transport.DoInitiator(ctx, n.clk, snd, p.inbox, n.self, n.psk, p.localIndex)
	if err != nil {
		return
	}
	if !n.requestAuth(ctx, p.addr, res) {
		return
	}
	sess := transport.NewSession(res)
	n.runSession(ctx, p, sess, res.FirstPayload, true)
}

func (n *Node) driveResponder(ctx context.Context, p *peer) {
	defer n.wg.Done()
	defer n.notifyDone(ctx, p.addr)
	snd := transport.AddrSender{Conn: n.conn, Addr: p.addr}
	res, err := transport.DoResponder(ctx, n.clk, snd, p.inbox, n.self, n.psk, p.localIndex)
	if err != nil {
		return
	}
	if !n.requestAuth(ctx, p.addr, res) {
		return
	}
	sess := transport.NewSession(res)
	n.runSession(ctx, p, sess, nil, false)
}

// runSession sends HELLO, starts the keep-alive, and processes inbound frames
// until ctx is canceled. A stray handshake frame (a retransmitted msg3 whose
// ack was lost) is answered idempotently by re-sending HELLO.
func (n *Node) runSession(ctx context.Context, p *peer, sess *transport.Session, firstPayload []byte, initiator bool) {
	hello := encodeHello(n.self.Label)
	n.sealSend(p.addr, sess, hello)

	// Publish the live session to the loop so it owns p.sess and can treat the
	// peer as SWIM-probeable + join-sync with it. The authenticated peer ID was
	// set by the loop in handleAuth before this driver resumed, so reading it
	// here is safe.
	fromID := p.nodeID
	n.sbAdd()
	select {
	case n.sessReady <- sessReadyMsg{addr: p.addr, sess: sess}:
	case <-ctx.Done():
		n.sbDone()
		sess.Close()
		return
	}

	if !n.disableKeepalive {
		n.wg.Add(1)
		go n.keepalive(ctx, p.addr, sess)
	}

	if initiator && n.greeting {
		n.sealSend(p.addr, sess, encodeText("hello from "+n.self.NodeID().Short()))
	}
	if firstPayload != nil {
		n.handleApp(ctx, p.addr, fromID, firstPayload)
	}

	for {
		select {
		case <-ctx.Done():
			sess.Close()
			return
		case b, ok := <-p.inbox:
			if !ok {
				sess.Close()
				return
			}
			// Every inbox frame reaching runSession was counted by handleInbound
			// (the peer is Connected), so retire exactly one unit per consumed
			// frame regardless of which branch handles it.
			n.processInboxFrame(ctx, p, sess, hello, fromID, b)
			n.sbDone()
		}
	}
}

// processInboxFrame handles one decrypted-or-handshake inbox frame. Any
// downstream work it triggers (a HELLO re-send, a SWIM envelope routed to the
// loop) is counted inside this call, before runSession retires the frame's own
// unit, so the barrier never dips to zero mid-reaction.
func (n *Node) processInboxFrame(ctx context.Context, p *peer, sess *transport.Session, hello []byte, fromID identity.NodeID, b []byte) {
	kind, err := transport.Classify(b)
	if err != nil {
		return
	}
	if kind == transport.KindHandshake {
		// Retransmitted handshake frame: re-send HELLO as the ack.
		n.sealSend(p.addr, sess, hello)
		return
	}
	pt, err := sess.OpenFrame(b)
	if err != nil {
		return // replay/forged/undecryptable - drop cheaply
	}
	n.handleApp(ctx, p.addr, fromID, pt)
}

func (n *Node) keepalive(ctx context.Context, addr netip.AddrPort, sess *transport.Session) {
	defer n.wg.Done()
	t := n.clk.NewTimer(n.keepaliveInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C():
			if !n.sealSend(addr, sess, encodeKeepalive()) {
				return
			}
			t.Reset(n.keepaliveInterval)
		}
	}
}

// sealSend encrypts and transmits one application message. It returns false if
// the session can no longer send (closed or nonce-exhausted).
func (n *Node) sealSend(addr netip.AddrPort, sess *transport.Session, msg []byte) bool {
	frame, err := sess.Seal(msg)
	if err != nil {
		return false
	}
	return n.conn.WriteTo(frame, addr) == nil
}

func (n *Node) handleApp(ctx context.Context, addr netip.AddrPort, fromID identity.NodeID, pt []byte) {
	m, ok := decodeMessage(pt)
	if !ok {
		return
	}
	if m.typ == msgSwim {
		// Route the SWIM envelope to the loop, tagged with the authenticated
		// peer identity, via a ctx-guarded send (never a bare blocking send).
		body := append([]byte(nil), m.body...)
		n.sbAdd()
		select {
		case n.swimIn <- swimInbound{fromID: fromID, fromAddr: addr, body: body}:
		case <-ctx.Done():
			n.sbDone()
		}
		return
	}
	u := lsUpdate{addr: addr, at: n.clk.Now()}
	if m.typ == msgHello {
		u.label = string(m.body)
		u.hasLabel = true
	}
	n.sbAdd()
	select {
	case n.lastSeen <- u:
	case <-ctx.Done():
		n.sbDone()
	}
}

func (n *Node) requestAuth(ctx context.Context, addr netip.AddrPort, res *transport.HandshakeResult) bool {
	reply := make(chan bool, 1)
	n.sbAdd() // auth request (retired by the loop after handleAuth)
	select {
	case n.auth <- &authReq{addr: addr, res: res, reply: reply}:
	case <-ctx.Done():
		n.sbDone()
		return false
	}
	select {
	case ok := <-reply:
		n.sbDone() // retire the loop's reply unit
		return ok
	case <-ctx.Done():
		return false
	}
}

func (n *Node) notifyDone(ctx context.Context, addr netip.AddrPort) {
	n.sbAdd()
	select {
	case n.done <- addr:
	case <-ctx.Done():
		n.sbDone()
	}
}

// Snapshot returns a point-in-time view of the peer table for the status
// renderer, read under the same mutex the loop writes under.
func (n *Node) Snapshot() []PeerView {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make([]PeerView, 0, len(n.byAddr))
	for _, p := range n.byAddr {
		out = append(out, PeerView{
			NodeID:   p.nodeID,
			Label:    p.label,
			Endpoint: p.addr,
			State:    p.state,
			LastSeen: p.lastSeen,
			HasID:    !p.nodeID.IsZero(),
		})
	}
	return out
}

// canonAddr normalizes an address so that an IPv4-mapped IPv6 form
// (::ffff:a.b.c.d, produced when a dual-stack socket talks to an IPv4 peer) and
// the plain IPv4 form key the same peer in the address table.
func canonAddr(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func randIndex() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}
