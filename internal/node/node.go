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
	"net/netip"
	"sync"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/clock"
	"github.com/MonkeyIsNull/DMesh/internal/discovery"
	"github.com/MonkeyIsNull/DMesh/internal/identity"
	"github.com/MonkeyIsNull/DMesh/internal/transport"
)

const (
	keepaliveInterval = 5 * time.Second
	fallbackDialDelay = 1 * time.Second
	halfOpenLimit     = 256
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

	wg sync.WaitGroup
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
	return &Node{
		self:      cfg.Identity,
		psk:       cfg.NetworkPSK,
		policy:    cfg.Policy,
		disc:      cfg.Discovery,
		conn:      cfg.Conn,
		clk:       cfg.Clock,
		enforce:   cfg.EnforceAllowList,
		greeting:  cfg.SendGreeting,
		byAddr:    make(map[netip.AddrPort]*peer),
		byID:      make(map[identity.NodeID]*peer),
		half:      transport.NewHalfOpenTable(halfOpenLimit),
		inbound:   make(chan inPkt, 256),
		hints:     make(chan discovery.PeerHint, 64),
		auth:      make(chan *authReq, 16),
		lastSeen:  make(chan lsUpdate, 256),
		done:      make(chan netip.AddrPort, 64),
		forceDial: make(chan forceDialReq, 64),
	}, nil
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
					select {
					case n.hints <- h:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	n.loop(ctx)
	// Unblock readLoop, which is parked in a blocking ReadFrom, so Run can
	// return once ctx is canceled. A second Close by the caller is harmless.
	_ = n.conn.Close()
	n.wg.Wait()
	return nil
}

// loop is the single event loop that owns the peer table.
func (n *Node) loop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pk := <-n.inbound:
			n.handleInbound(ctx, pk)
		case h := <-n.hints:
			n.handleHint(ctx, h)
		case a := <-n.auth:
			n.handleAuth(a)
		case u := <-n.lastSeen:
			n.handleLastSeen(u)
		case addr := <-n.done:
			n.handleDone(addr)
		case fd := <-n.forceDial:
			n.handleForceDial(ctx, fd)
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
		select {
		case n.inbound <- inPkt{addr: canonAddr(addr), data: data}:
		case <-ctx.Done():
			return
		}
	}
}

func (n *Node) handleInbound(ctx context.Context, pk inPkt) {
	if p := n.byAddr[pk.addr]; p != nil && p.inbox != nil {
		select {
		case p.inbox <- pk.data:
		default: // peer's inbox is full; drop (UDP semantics)
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
		return
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
		t := n.clk.NewTimer(fallbackDialDelay)
		defer t.Stop()
		select {
		case <-ctx.Done():
		case <-t.C():
			select {
			case n.forceDial <- forceDialReq{addr: addr, nodeID: nid, label: h.Label}:
			case <-ctx.Done():
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

func (n *Node) handleAuth(a *authReq) {
	n.mu.Lock()
	defer n.mu.Unlock()
	p := n.byAddr[a.addr]
	if p == nil {
		a.reply <- false
		return
	}
	if n.policy(a.res.PeerNodeID) == transport.TrustReject {
		p.state = StateFailed
		a.reply <- false
		return
	}
	// Identity-keyed collapse: if a connected session already exists for this
	// authenticated node ID, drop the newer one (keep exactly one stable
	// session per peer identity).
	if ex := n.byID[a.res.PeerNodeID]; ex != nil && ex != p && ex.state == StateConnected {
		a.reply <- false
		return
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
	a.reply <- true
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

	n.wg.Add(1)
	go n.keepalive(ctx, p.addr, sess)

	if initiator && n.greeting {
		n.sealSend(p.addr, sess, encodeText("hello from "+n.self.NodeID().Short()))
	}
	if firstPayload != nil {
		n.handleApp(ctx, p.addr, firstPayload)
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
			kind, err := transport.Classify(b)
			if err != nil {
				continue
			}
			if kind == transport.KindHandshake {
				// Retransmitted handshake frame: re-send HELLO as the ack.
				n.sealSend(p.addr, sess, hello)
				continue
			}
			pt, err := sess.OpenFrame(b)
			if err != nil {
				continue // replay/forged/undecryptable - drop cheaply
			}
			n.handleApp(ctx, p.addr, pt)
		}
	}
}

func (n *Node) keepalive(ctx context.Context, addr netip.AddrPort, sess *transport.Session) {
	defer n.wg.Done()
	t := n.clk.NewTimer(keepaliveInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C():
			if !n.sealSend(addr, sess, encodeKeepalive()) {
				return
			}
			t.Reset(keepaliveInterval)
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

func (n *Node) handleApp(ctx context.Context, addr netip.AddrPort, pt []byte) {
	m, ok := decodeMessage(pt)
	if !ok {
		return
	}
	u := lsUpdate{addr: addr, at: n.clk.Now()}
	if m.typ == msgHello {
		u.label = string(m.body)
		u.hasLabel = true
	}
	select {
	case n.lastSeen <- u:
	case <-ctx.Done():
	}
}

func (n *Node) requestAuth(ctx context.Context, addr netip.AddrPort, res *transport.HandshakeResult) bool {
	reply := make(chan bool, 1)
	select {
	case n.auth <- &authReq{addr: addr, res: res, reply: reply}:
	case <-ctx.Done():
		return false
	}
	select {
	case ok := <-reply:
		return ok
	case <-ctx.Done():
		return false
	}
}

func (n *Node) notifyDone(ctx context.Context, addr netip.AddrPort) {
	select {
	case n.done <- addr:
	case <-ctx.Done():
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
