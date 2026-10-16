package node

import (
	"context"
	"net/netip"
	"sort"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
	"github.com/MonkeyIsNull/DMesh/internal/nat"
	"github.com/MonkeyIsNull/DMesh/internal/transport"
)

// relay_loop.go is Phase 1: relay circuits. A relay R is a DUMB PIPE: it forwards
// sealed inner frames it cannot read, only between two credentialed endpoints
// bound to a circuit, bounded by per-circuit/per-requester/global byte buckets
// and circuit caps, and it never dials on demand (no reflection/amplification to
// a non-member). Endpoints carry a relayed peer under an undialable fdme::
// pseudo-address keyed by circuit id; every send to it goes through sendToPeer,
// which wraps it onto the carrier. All work is on the event loop except the
// bounded off-loop forwarder (nat_node.go), which only does Seal+WriteTo on a
// carrier pointer resolved on the loop.

// pendingOpen records a circuit-open this node issued as an opener, so a
// circOpenAck is matched to its intended target.
type pendingOpen struct {
	relay  identity.NodeID
	target identity.NodeID
	label  string
	// at is when the open was issued, on the injected clock. sweepPendingOpens
	// removes entries older than PendingOpenTimeout so a lost circOpen/circOpenAck
	// cannot leak the entry (and wedge reopen/dial dedup to the target) forever.
	at time.Time
}

// allowedForRelay reports whether id may participate in a relay circuit with us:
// under allow-list enforcement it must be a trusted member; otherwise (TOFU) any
// authenticated member is allowed.
func (n *Node) allowedForRelay(id identity.NodeID) bool {
	if id.IsZero() {
		return false
	}
	if !n.enforce {
		return true
	}
	return n.policy(id) == transport.TrustAccept
}

// handleCircuitIn dispatches one authenticated circuit-control message.
func (n *Node) handleCircuitIn(ctx context.Context, in circuitInbound) {
	m, ok := nat.DecodeRelay(in.body)
	if !ok {
		return // unknown version/sub/truncation: silent drop
	}
	now := n.clk.Now()
	switch m.Sub {
	case nat.CircOpen:
		n.handleCircOpen(in, m, now)
	case nat.CircOpenAck:
		n.handleCircOpenAck(ctx, in, m)
	case nat.CircOpenNotify:
		n.handleCircOpenNotify(ctx, in, m)
	case nat.CircData:
		n.handleCircData(ctx, in, m, now)
	case nat.CircClose:
		n.handleCircClose(in, m)
	}
}

// handleCircOpen runs on the relay R. It opens a circuit ONLY if the opener and
// target are both credentialed and R currently holds a direct connected session
// to the target. Otherwise it denies and sends nothing to anyone (no on-demand
// dial - mirrors handlePingReq's silence).
func (n *Node) handleCircOpen(in circuitInbound, m nat.RelayMsg, now time.Time) {
	if !n.relayRole {
		n.sendCircControl(in.fromID, nat.EncodeCircOpenAck(m.ReqNonce, nat.CircStatusNoCap, 0))
		return
	}
	n.mu.RLock()
	tp := n.byID[m.Target]
	targetOK := tp != nil && tp.state == StateConnected && tp.sess != nil && tp.path.kind == pathDirect
	n.mu.RUnlock()
	if !targetOK || !n.allowedForRelay(in.fromID) || !n.allowedForRelay(m.Target) || m.Target == n.self.NodeID() {
		n.sendCircControl(in.fromID, nat.EncodeCircOpenAck(m.ReqNonce, nat.CircStatusDenied, 0))
		return
	}
	// Allocate a (collision-free) circuit id from the injectable RNG.
	var id nat.CircuitID
	for i := 0; i < 8; i++ {
		id = nat.CircuitID(n.circuitRnd.Uint64())
		if id != 0 && !n.circuitTbl.Exists(id) {
			break
		}
	}
	cid, res := n.circuitTbl.Open(in.fromID, m.Target, m.ReqNonce, id, now)
	switch res {
	case nat.OpenOK:
		n.sendCircControl(in.fromID, nat.EncodeCircOpenAck(m.ReqNonce, nat.CircStatusOK, cid))
		n.sendCircControl(m.Target, nat.EncodeCircOpenNotify(in.fromID, cid))
	case nat.OpenRateLimited:
		n.sendCircControl(in.fromID, nat.EncodeCircOpenAck(m.ReqNonce, nat.CircStatusRateLimited, 0))
	default:
		n.sendCircControl(in.fromID, nat.EncodeCircOpenAck(m.ReqNonce, nat.CircStatusDenied, 0))
	}
}

// handleCircOpenAck runs on the opener A. On success it creates the relayed peer
// for the INTENDED target and starts the handshake per the lexicographic node-ID
// election (the smaller id dials; the larger waits for the inner msg1 over the
// circuit). in.fromID is the relay.
func (n *Node) handleCircOpenAck(ctx context.Context, in circuitInbound, m nat.RelayMsg) {
	po, ok := n.pendingOpens[m.ReqNonce]
	if !ok || po.relay != in.fromID {
		return
	}
	delete(n.pendingOpens, m.ReqNonce)
	if m.Status != nat.CircStatusOK {
		return
	}
	if _, exists := n.circuits[m.CircuitID]; exists {
		return
	}
	if n.self.NodeID().String() < po.target.String() {
		n.startRelayedInitiator(ctx, po.relay, po.target, m.CircuitID)
	} else {
		n.startRelayedResponder(ctx, po.relay, po.target, m.CircuitID)
	}
}

// handleCircOpenNotify runs on the target B. B gates independently: it allocates
// no state unless it allow-lists the claimed source AND the relay, the relayed
// caps allow, and the circuit is not already known. Then the election decides who
// dials.
func (n *Node) handleCircOpenNotify(ctx context.Context, in circuitInbound, m nat.RelayMsg) {
	src := m.Source
	if src.IsZero() || src == n.self.NodeID() {
		return
	}
	if !n.allowedForRelay(src) || !n.allowedForRelay(in.fromID) {
		return
	}
	if _, exists := n.circuits[m.CircuitID]; exists {
		return
	}
	if n.self.NodeID().String() < src.String() {
		n.startRelayedInitiator(ctx, in.fromID, src, m.CircuitID)
	} else {
		n.startRelayedResponder(ctx, in.fromID, src, m.CircuitID)
	}
}

// handleCircData either forwards (we are the relay) or unwraps to a relayed
// peer's inbox (we are an endpoint).
func (n *Node) handleCircData(ctx context.Context, in circuitInbound, m nat.RelayMsg, now time.Time) {
	// Endpoint path: we hold (or can create) the relayed peer for this circuit.
	if p := n.circuits[m.CircuitID]; p != nil {
		n.deliverRelayedInbound(p, m.Payload)
		return
	}
	// Relay path: forward between the two bound endpoints iff from is bound.
	if other, ok := n.circuitTbl.Other(m.CircuitID, in.fromID); ok {
		inner := append([]byte(nil), m.Payload...)
		// Rate policy. DATA frames, and any frame that is not a well-formed
		// handshake frame (including a malformed/garbage frame that fails Classify),
		// always draw on the byte buckets. A handshake frame is exempt ONLY while
		// the circuit's bounded, one-time handshake-grace budget covers it; once
		// that grace is spent, handshake frames are charged exactly like data. This
		// keeps a legitimate in-flight handshake from being starved by a rate limit
		// while closing the bypass where every non-DATA frame fell through to a
		// Touch-only path and forwarded uncharged - a flood of handshake-typed or
		// garbage frames can no longer defeat the per-circuit/per-requester/global
		// ceilings.
		charge := true
		if kind, err := transport.Classify(inner); err == nil && kind == transport.KindHandshake {
			if n.circuitTbl.ConsumeHandshakeGrace(m.CircuitID, len(inner)) {
				charge = false
			}
		}
		if charge {
			if !n.circuitTbl.ChargeGlobal(len(inner), now) {
				return // shed first under global pressure
			}
			if !n.circuitTbl.Charge(m.CircuitID, len(inner), now) {
				return // per-circuit / per-requester over budget: drop
			}
		} else {
			n.circuitTbl.Touch(m.CircuitID, now)
		}
		n.mu.RLock()
		op := n.byID[other]
		var carrier *transport.Session
		var relayAddr netip.AddrPort
		if op != nil && op.path.kind == pathDirect {
			carrier = op.sess
			relayAddr = op.addr
		}
		n.mu.RUnlock()
		if carrier == nil {
			return
		}
		n.enqueueForward(ctx, fwdReq{
			carrier:   carrier,
			relayAddr: relayAddr,
			wrapped:   encodeRelay(nat.EncodeCircData(m.CircuitID, inner)),
		})
		return
	}
	// Unknown circuit on this endpoint: no circuit entry exists, so no
	// circOpenNotify has admitted a relayed responder for this id. A relayed
	// responder is admitted ONLY by handleCircOpenNotify, which gates on an
	// authorized relay AND an allow-listed source AND the relayed caps. We must
	// NOT manufacture a responder here from an arbitrary direct peer's unsolicited
	// circData for an unknown circuit: doing so would spawn a driveResponder
	// goroutine that bypasses the design's single admission point, and it is
	// insider-reachable (any credentialed direct peer could send such a frame).
	// A legitimately set-up circuit is already handled by the endpoint path above
	// (its notify created the circuit entry); a genuinely reordered first-data
	// frame that raced ahead of its own notify is safely dropped here - the notify
	// then creates the entry and the initiator's handshake RTO retransmits msg1,
	// which the endpoint path delivers. With no authorized circuit or notify, drop.
}

// handleCircClose tears down a circuit. An endpoint accepts it only from the
// relay that owns the circuit; a relay accepts it only from a bound endpoint and
// forwards a close to the other endpoint.
func (n *Node) handleCircClose(in circuitInbound, m nat.RelayMsg) {
	if p := n.circuits[m.CircuitID]; p != nil {
		if p.path.relay != in.fromID {
			return // only the owning relay may close an endpoint's circuit
		}
		if p.cancel != nil {
			p.cancel() // handleDone removes byAddr/byID/circuits atomically
		}
		return
	}
	if other, ok := n.circuitTbl.Other(m.CircuitID, in.fromID); ok {
		n.circuitTbl.Close(m.CircuitID)
		n.sendCircControl(other, nat.EncodeCircClose(m.CircuitID, m.Code))
	}
}

// deliverRelayedInbound pushes an unwrapped inner datagram to a relayed peer's
// inbox using EXACTLY handleInbound's barrier discipline: count the loop->driver
// hand-off only once the peer is Connected (runSession is then the consumer that
// retires it); during the handshake the transport state machine drains the inbox
// and cannot retire, so those frames are left uncounted.
func (n *Node) deliverRelayedInbound(p *peer, payload []byte) {
	if p.inbox == nil {
		return
	}
	data := append([]byte(nil), payload...)
	if p.state == StateConnected {
		n.sbAdd()
		select {
		case p.inbox <- data:
		default:
			n.sbDone()
		}
		return
	}
	select {
	case p.inbox <- data:
	default:
	}
}

// --- relayed peer creation --------------------------------------------------

// relayedAdmit checks the per-relay and global relayed-peer caps and increments
// the counters. The caller is on the loop. Relayed peers are tracked SEPARATELY
// from the direct half-open table so they can never evict direct handshakes.
func (n *Node) relayedAdmit(relay identity.NodeID) bool {
	if n.relayedTotal >= n.natParams.MaxInboundCircuitsPerNode {
		return false
	}
	if n.relayedHalf[relay] >= n.natParams.MaxInboundCircuitsPerRelay {
		return false
	}
	n.relayedHalf[relay]++
	n.relayedTotal++
	return true
}

// newRelayedPeer creates and registers a relayed peer under its pseudo-address
// and circuit id. intended is the target/source identity used by the
// confirm-identity-post-handshake check (may be zero for the reorder case). The
// caller must NOT hold n.mu.
func (n *Node) newRelayedPeer(ctx context.Context, relay, intended identity.NodeID, circuit nat.CircuitID, initiator bool) *peer {
	pa := pseudoAddr(relay, circuit)
	n.mu.Lock()
	if n.byAddr[pa] != nil || n.circuits[circuit] != nil {
		n.mu.Unlock()
		return nil
	}
	pctx, cancel := context.WithCancel(ctx)
	p := &peer{
		addr:       pa,
		inbox:      make(chan []byte, 64),
		cancel:     cancel,
		initiator:  initiator,
		nodeID:     intended,
		state:      StateHandshaking,
		localIndex: randIndex(),
		path:       peerPath{kind: pathRelay, relay: relay, circuit: circuit},
		// Seed lastSeen now so the endpoint-side idle reaper does not tear down a
		// peer that is still handshaking (its lastSeen would otherwise be the zero
		// time, i.e. idle forever).
		lastSeen: n.clk.Now(),
	}
	n.byAddr[pa] = p
	n.circuits[circuit] = p
	n.mu.Unlock()

	n.wg.Add(1)
	if initiator {
		go n.driveInitiator(pctx, p)
	} else {
		go n.driveResponder(pctx, p)
	}
	return p
}

// startRelayedInitiator / startRelayedResponder are the ONLY two relayed-peer
// creation sites, and each admits exactly once against the relayed caps (balanced
// by handleDone's decrement on teardown). There is no "unknown circuit" creation
// site: a relayed responder is admitted solely by handleCircOpenNotify, never
// manufactured from an unsolicited circData for an unknown circuit.
func (n *Node) startRelayedInitiator(ctx context.Context, relay, target identity.NodeID, circuit nat.CircuitID) {
	if !n.relayedAdmit(relay) {
		return
	}
	if n.newRelayedPeer(ctx, relay, target, circuit, true) == nil {
		n.relayedRelease(relay)
	}
}

func (n *Node) startRelayedResponder(ctx context.Context, relay, source identity.NodeID, circuit nat.CircuitID) {
	if !n.relayedAdmit(relay) {
		return
	}
	if n.newRelayedPeer(ctx, relay, source, circuit, false) == nil {
		n.relayedRelease(relay)
	}
}

// relayedRelease rolls back a relayedAdmit when peer creation did not happen.
func (n *Node) relayedRelease(relay identity.NodeID) {
	if c := n.relayedHalf[relay]; c > 0 {
		n.relayedHalf[relay] = c - 1
		if n.relayedHalf[relay] == 0 {
			delete(n.relayedHalf, relay)
		}
	}
	if n.relayedTotal > 0 {
		n.relayedTotal--
	}
}

// --- circuit open initiation (opener side) ----------------------------------

// reopenCircuit is the relay fallback for a paused session with no real direct
// candidate: it opens a circuit through a connected CapRelay member to the peer.
// It never dials the pseudo-address. Runs on the loop.
func (n *Node) reopenCircuit(target identity.NodeID) {
	n.mu.RLock()
	if p := n.byID[target]; p != nil && (p.state == StateHandshaking || p.state == StateConnected) {
		n.mu.RUnlock()
		return
	}
	// Deduplicate against an open already in flight to this target.
	for _, po := range n.pendingOpens {
		if po.target == target {
			n.mu.RUnlock()
			return
		}
	}
	// Pick the lexicographically-smallest connected CapRelay member (deterministic).
	var relayID identity.NodeID
	have := false
	for id, p := range n.byID {
		if id == target || p.state != StateConnected || p.sess == nil || p.path.kind != pathDirect {
			continue
		}
		cs := n.candStore[id]
		if cs == nil || cs.Caps&nat.CapRelay == 0 {
			continue
		}
		if !have || id.String() < relayID.String() {
			relayID = id
			have = true
		}
	}
	n.mu.RUnlock()
	if !have {
		return
	}
	n.openCircuit(relayID, target)
}

// circDialReq asks the loop to open a circuit to target through relay (used by
// the DialViaRelay API / the deterministic sim helper).
type circDialReq struct {
	relay  identity.NodeID
	target identity.NodeID
}

// DialViaRelay explicitly opens a relay circuit to target through relay, used by
// the app/CLI (and the deterministic sim) when the direct path is known to be
// unavailable. It routes the request to the loop (single writer).
func (n *Node) DialViaRelay(ctx context.Context, relay, target identity.NodeID) {
	n.sbAdd()
	select {
	case n.circDial <- circDialReq{relay: relay, target: target}:
	case <-ctx.Done():
		n.sbDone()
	}
}

func (n *Node) handleCircDial(d circDialReq) {
	// Deduplicate against an in-flight open or an existing live peer to target.
	n.mu.RLock()
	if p := n.byID[d.target]; p != nil && (p.state == StateHandshaking || p.state == StateConnected) {
		n.mu.RUnlock()
		return
	}
	n.mu.RUnlock()
	for _, po := range n.pendingOpens {
		if po.target == d.target && po.relay == d.relay {
			return
		}
	}
	n.openCircuit(d.relay, d.target)
}

// openCircuit records a pending open and sends a circOpen to the relay. Runs on
// the loop.
func (n *Node) openCircuit(relay, target identity.NodeID) {
	nonce := n.circuitRnd.Uint32()
	for i := 0; i < 8; i++ {
		if _, dup := n.pendingOpens[nonce]; !dup && nonce != 0 {
			break
		}
		nonce = n.circuitRnd.Uint32()
	}
	n.pendingOpens[nonce] = pendingOpen{relay: relay, target: target, at: n.clk.Now()}
	n.sendCircControl(relay, nat.EncodeCircOpen(target, nonce))
}

// sweepPendingOpens removes circuit-open entries this node issued that have gone
// unacked past PendingOpenTimeout. Without it, a single lost circOpen or
// circOpenAck (the ordinary case on the lossy/NAT paths where relay is used)
// leaks the entry permanently: handleCircOpenAck is the only other deleter and
// it only fires on an ack, while reopenCircuit/handleCircDial dedup against the
// entry by target - so the relay fallback (durable-session resume) to that
// target would be wedged forever and the map would grow unbounded. After a
// sweep, the next session tick re-issues the open. Runs on the loop.
func (n *Node) sweepPendingOpens(now time.Time) {
	for nonce, po := range n.pendingOpens {
		if now.Sub(po.at) >= n.natParams.PendingOpenTimeout {
			delete(n.pendingOpens, nonce)
		}
	}
}

// --- control send + reaping + teardown --------------------------------------

// sendCircControl seals a circuit-control body on the DIRECT session to toID and
// sends it (control frames ride the direct carrier, never wrapped in circData).
func (n *Node) sendCircControl(toID identity.NodeID, body []byte) {
	n.mu.RLock()
	p := n.byID[toID]
	var sess *transport.Session
	if p != nil {
		sess = p.sess
	}
	n.mu.RUnlock()
	if p == nil || sess == nil {
		return
	}
	n.sealSend(p, sess, encodeRelay(body))
}

// sortPeersByCircuit orders relayed peers by circuit id for deterministic
// teardown emission.
func sortPeersByCircuit(ps []*peer) {
	sort.Slice(ps, func(i, j int) bool { return ps[i].path.circuit < ps[j].path.circuit })
}

// emitCircClose sends a circClose for a deferred teardown intent collected under
// n.mu in handleAuth (emitted after the lock is released).
func (n *Node) emitCircClose(pc *pendingCircClose) {
	if pc == nil {
		return
	}
	n.sendCircControl(pc.relay, nat.EncodeCircClose(pc.circuit, 0))
}

// reapCircuits reaps idle relay circuits (relay side) and idle relayed peers
// (endpoint side) on the injected clock. Relay-side reaped ids come back sorted,
// so circClose emissions are deterministic.
func (n *Node) reapCircuits(now time.Time) {
	// Relay side: ReapIdleWithEndpoints captures each circuit's endpoints BEFORE
	// closing it, so the relay can still notify both sides; ids come back sorted.
	for _, rc := range n.circuitTbl.ReapIdleWithEndpoints(now) {
		n.sendCircControl(rc.A, nat.EncodeCircClose(rc.ID, 0))
		n.sendCircControl(rc.B, nat.EncodeCircClose(rc.ID, 0))
	}
	// Endpoint side: tear down a relayed peer idle past CircuitIdleTimeout. Sort
	// the victims by circuit id for deterministic emission.
	n.mu.RLock()
	var stale []*peer
	for _, p := range n.circuits {
		if now.Sub(p.lastSeen) >= n.natParams.CircuitIdleTimeout {
			stale = append(stale, p)
		}
	}
	n.mu.RUnlock()
	sortPeersByCircuit(stale)
	for _, p := range stale {
		if p.cancel != nil {
			p.cancel()
		}
		n.sendCircControl(p.path.relay, nat.EncodeCircClose(p.path.circuit, 0))
	}
}
