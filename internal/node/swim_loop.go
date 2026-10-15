package node

import (
	"bytes"
	"net/netip"
	"sort"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/discovery"
	"github.com/MonkeyIsNull/DMesh/internal/identity"
	"github.com/MonkeyIsNull/DMesh/internal/swim"
	"github.com/MonkeyIsNull/DMesh/internal/transport"
)

// swim_loop.go wires the pure swim core into the single-owner event loop. All
// SWIM state (roster, gossip buffer, detector, relay table) is touched ONLY by
// the loop goroutine. The roster is additionally guarded by n.mu because the
// status renderer reads it; the gossip buffer, detector, and relay table are
// loop-private and need no lock.
//
// Every SWIM send is a direct, synchronous Seal through the peer's loop-owned
// session (no per-peer send goroutine, no send channel): Session.Seal is
// concurrency-safe, so the loop Sealing alongside the driver's
// keepalive/runSession is sound, and there is no channel to close, overflow, or
// deadlock on.

// handlePhase runs one of the three protocol-period phases.
func (n *Node) handlePhase(phase int) {
	now := n.clk.Now()
	switch phase {
	case 0:
		// Period start: promote expired suspects, reap, then probe a new target.
		n.mu.Lock()
		dead := n.roster.Tick(now)
		sends := n.params.RetransmitCount(n.roster.Size())
		probeable := n.probeableIDsLocked()
		n.mu.Unlock()
		n.reapRelayPending(now)
		for _, u := range dead {
			n.gossip.Add(u, sends)
		}
		n.startProbe(probeable)
		// Proactively nudge any member we hold as Suspect/Dead but still have a
		// live session to: hand it our view so it refutes. This is the key guard
		// against a *reachable* (merely lossy) member being falsely declared Dead
		// — it gives the member a fresh chance every period to refute, long
		// before the suspicion timer could expire. Truly-gone members have no
		// live session and are untouched (they correctly proceed to Dead).
		n.nudgeStaleConnected()
	case 1:
		n.indirectProbe()
	case 2:
		n.expireProbe(now)
	}
}

// startProbe picks this period's direct-ping target and sends it a ping.
func (n *Node) startProbe(probeable []identity.NodeID) {
	seq := n.nextSeq()
	target, ok := n.detector.StartPeriod(probeable, seq, n.rng)
	if !ok {
		return
	}
	p := n.byID[target]
	if p == nil || p.sess == nil {
		return
	}
	n.sealSend(p.addr, p.sess, n.buildSwimFrame(swim.KindPing, seq, identity.NodeID{}, netip.AddrPort{}))
}

// indirectProbe asks K random relays to ping-req the still-unacked target.
func (n *Node) indirectProbe() {
	target, seq, ok := n.detector.Indirect()
	if !ok {
		return
	}
	relays := n.pickRelays(target, n.params.K)
	var targetEP netip.AddrPort
	n.mu.Lock()
	if m := n.byID[target]; m != nil {
		targetEP = m.addr
	}
	n.mu.Unlock()
	for _, r := range relays {
		n.sealSend(r.addr, r.sess, n.buildSwimFrame(swim.KindPingReq, seq, target, targetEP))
	}
}

// expireProbe applies the failure-detector verdict at period end: if the target
// never acked (directly or indirectly), mark it Suspect and gossip that.
func (n *Node) expireProbe(now time.Time) {
	target, ok := n.detector.Expire()
	if !ok {
		return
	}
	n.mu.Lock()
	u := n.roster.LocalSuspect(target, now)
	sends := n.params.RetransmitCount(n.roster.Size())
	n.mu.Unlock()
	if u != nil {
		n.gossip.Add(*u, sends)
	}
}

// handleSwimIn processes one decoded SWIM envelope from an authenticated peer.
func (n *Node) handleSwimIn(in swimInbound) {
	env, ok := swim.Decode(in.body)
	if !ok {
		return // malformed/over-cap/unknown: cheap drop, no panic
	}
	now := n.clk.Now()

	// Liveness bookkeeping only (never rewrites roster state).
	n.detector.AckFrom(in.fromID)

	var regossip []swim.Update
	var hints []discovery.PeerHint
	n.mu.Lock()
	var reconAddr netip.AddrPort
	var reconSess *transport.Session
	var reconBurst []swim.Update
	if p := n.byAddr[in.fromAddr]; p != nil {
		p.lastSeen = now
		// Connectivity-triggered reconciliation: a directly-connected peer whose
		// roster state we hold as Suspect/Dead just proved liveness. We do NOT
		// rewrite its state from the frame (strict liveness/state separation);
		// instead we hand it our view (which carries the stale Suspect/Dead about
		// IT) so it refutes with a higher incarnation. This is the join-sync
		// reconciliation of §1.4 triggered by a healed link rather than a new
		// handshake, and it is bounded (one burst) and self-limiting (once the
		// peer refutes, we see it Alive and stop).
		if st, ok := n.roster.State(in.fromID); ok && (st == swim.StateSuspect || st == swim.StateDead) && p.sess != nil && !n.disableJoinSync {
			reconAddr = p.addr
			reconSess = p.sess
			reconBurst = n.roster.GossipRows(n.params.MaxPiggyback)
		}
	}
	// Per-frame self-incarnation clamp: within ONE frame, apply only the single
	// highest-incarnation update about ourselves. The lattice join is idempotent
	// on the maximum, so this reaches the same selfInc as applying that maximum
	// alone — but it stops a crafted frame of ascending Suspect{self,...} entries
	// from walking selfInc up ~MaxSelfIncJump per entry (≈1000/frame), which
	// would otherwise partly defeat MaxSelfIncJump's purpose of bounding forged
	// self-incarnation inflation. Non-self updates are unaffected.
	self := n.self.NodeID()
	bestSelf := -1
	for i, u := range env.Updates {
		if u.NodeID == self {
			if bestSelf < 0 || u.Incarnation > env.Updates[bestSelf].Incarnation {
				bestSelf = i
			}
		}
	}
	for i, u := range env.Updates {
		if u.NodeID == self && i != bestSelf {
			continue // drop redundant self-updates within this frame
		}
		res := n.roster.Apply(u, now)
		if res.Regossip != nil {
			regossip = append(regossip, *res.Regossip)
		}
		if res.Refutation != nil {
			regossip = append(regossip, *res.Refutation)
		}
		if res.LearnedEndpoint.IsValid() && !n.disableGossipDial {
			if h, ok := n.dialHintLocked(u.NodeID, res.LearnedEndpoint); ok {
				hints = append(hints, h)
			}
		}
	}
	sends := n.params.RetransmitCount(n.roster.Size())
	n.mu.Unlock()

	if reconSess != nil && len(reconBurst) > 0 {
		env := swim.Envelope{Kind: swim.KindSync, Seq: n.nextSeq(), Updates: reconBurst}
		n.sealSend(reconAddr, reconSess, encodeSwim(swim.Encode(env)))
	}
	for _, u := range regossip {
		n.gossip.Add(u, sends)
	}
	for _, h := range hints {
		n.sbAdd()
		select {
		case n.hints <- h:
		default: // hints buffer full: drop, discovery will re-announce
			n.sbDone()
		}
	}

	switch env.Kind {
	case swim.KindPing:
		n.replyAck(in.fromID, env.Seq)
	case swim.KindAck:
		n.detector.Ack(env.Seq)
		n.forwardRelayAck(env.Seq)
	case swim.KindPingReq:
		n.handlePingReq(in.fromID, env, now)
	case swim.KindPingReqAck:
		n.detector.Ack(env.Seq)
	case swim.KindSync:
		// Join-sync burst: updates already merged above. No reply — both sides
		// publish a sync burst on connect, so the exchange is bidirectional.
	}
}

// replyAck answers a direct ping with an ack (piggybacking gossip).
func (n *Node) replyAck(toID identity.NodeID, seq uint32) {
	p := n.byID[toID]
	if p == nil || p.sess == nil {
		return
	}
	n.sealSend(p.addr, p.sess, n.buildSwimFrame(swim.KindAck, seq, identity.NodeID{}, netip.AddrPort{}))
}

// handlePingReq is the relay path: if we hold a live session to the target, ping
// it on the requester's behalf and remember to forward the ack. If not, stay
// silent — silence is not death, and we never dial on demand (a handshake
// dwarfs the T/3 window and on-demand dialing is a reflection/dial-storm
// vector).
func (n *Node) handlePingReq(fromID identity.NodeID, env swim.Envelope, now time.Time) {
	target := env.Target
	if target.IsZero() || target == n.self.NodeID() {
		return
	}
	tp := n.byID[target]
	if tp == nil || tp.sess == nil || tp.state != StateConnected {
		return
	}
	newSeq := n.nextSeq()
	n.relayPending[newSeq] = relayReq{
		requester: fromID,
		reqSeq:    env.Seq,
		target:    target,
		deadline:  now.Add(n.params.T),
	}
	n.sealSend(tp.addr, tp.sess, n.buildSwimFrame(swim.KindPing, newSeq, identity.NodeID{}, netip.AddrPort{}))
}

// forwardRelayAck, on an ack to one of our relay pings, forwards a ping-req-ack
// to the original requester.
func (n *Node) forwardRelayAck(seq uint32) {
	rp, ok := n.relayPending[seq]
	if !ok {
		return
	}
	delete(n.relayPending, seq)
	rq := n.byID[rp.requester]
	if rq == nil || rq.sess == nil {
		return
	}
	n.sealSend(rq.addr, rq.sess, n.buildSwimFrame(swim.KindPingReqAck, rp.reqSeq, rp.target, netip.AddrPort{}))
}

// nudgeStaleConnected sends a reconciliation burst to every member we hold as
// Suspect/Dead but still have a live session to, so a reachable member refutes
// promptly. Bounded by the number of connected peers.
func (n *Node) nudgeStaleConnected() {
	if n.disableJoinSync {
		return
	}
	n.mu.Lock()
	var targets []*peer
	var burst []swim.Update
	for _, r := range n.roster.Rows() {
		if r.IsSelf || (r.State != swim.StateSuspect && r.State != swim.StateDead) {
			continue
		}
		if p := n.byID[r.ID]; p != nil && p.sess != nil && p.state == StateConnected {
			targets = append(targets, p)
		}
	}
	if len(targets) > 0 {
		burst = n.roster.GossipRows(n.params.MaxPiggyback)
	}
	n.mu.Unlock()
	// Send as a KindPing carrying our explicit roster view (which includes the
	// stale Suspect/Dead about the target). The target merges it, refutes with a
	// higher incarnation, and its ACK carries that refutation straight back to
	// us — one direct round trip, independent of round-robin gossip timing.
	for _, p := range targets {
		env := swim.Envelope{Kind: swim.KindPing, Seq: n.nextSeq(), Updates: burst}
		n.sealSend(p.addr, p.sess, encodeSwim(swim.Encode(env)))
	}
}

func (n *Node) reapRelayPending(now time.Time) {
	for seq, rp := range n.relayPending {
		if !now.Before(rp.deadline) {
			delete(n.relayPending, seq)
		}
	}
}

// handleSessReady records a newly-live session on the peer and performs the
// mandatory bidirectional join-sync: observe the peer Alive, stop suspecting it
// (handshake-as-ground-truth), and ship a bounded priority-ordered roster burst
// so a rejoining/stale node learns it must refute and a fresh node is seeded
// with the mesh view it never discovered.
func (n *Node) handleSessReady(m sessReadyMsg) {
	now := n.clk.Now()
	n.mu.Lock()
	p := n.byAddr[m.addr]
	if p == nil {
		n.mu.Unlock()
		return
	}
	p.sess = m.sess
	peerID := p.nodeID
	addr := p.addr
	var obs *swim.Update
	if !peerID.IsZero() {
		obs = n.roster.Observe(peerID, addr, now)
	}
	sends := n.params.RetransmitCount(n.roster.Size())
	var burst []swim.Update
	if !n.disableJoinSync {
		burst = n.roster.GossipRows(n.params.MaxPiggyback)
	}
	n.mu.Unlock()

	if !peerID.IsZero() {
		n.detector.AckFrom(peerID)
	}
	if obs != nil {
		n.gossip.Add(*obs, sends)
	}
	if len(burst) > 0 {
		seq := n.nextSeq()
		env := swim.Envelope{Kind: swim.KindSync, Seq: seq, Updates: burst}
		n.sealSend(addr, m.sess, encodeSwim(swim.Encode(env)))
	}
}

// handleLeave announces a graceful departure: bump+persist the incarnation,
// apply Left locally, and flush it to every connected peer with an elevated
// send-count so the mesh records a leave (not a failure cascade).
func (n *Node) handleLeave() {
	n.mu.Lock()
	left := n.roster.Leave()
	sends := n.params.RetransmitCount(n.roster.Size()) * 2
	conns := n.connectedPeersLocked()
	n.mu.Unlock()

	n.gossip.Add(left, sends)
	for _, p := range conns {
		seq := n.nextSeq()
		env := swim.Envelope{Kind: swim.KindSync, Seq: seq, Updates: []swim.Update{left}}
		n.sealSend(p.addr, p.sess, encodeSwim(swim.Encode(env)))
	}
}

// --- helpers ---------------------------------------------------------------

func (n *Node) nextSeq() uint32 {
	n.swimSeq++
	return n.swimSeq
}

// buildSwimFrame encodes an envelope with up-to-MaxPiggyback gossip updates
// picked (and decremented) from the buffer.
func (n *Node) buildSwimFrame(kind uint8, seq uint32, target identity.NodeID, targetEP netip.AddrPort) []byte {
	updates := n.gossip.Pick(n.params.MaxPiggyback)
	env := swim.Envelope{Kind: kind, Seq: seq, Target: target, TargetEndpoint: targetEP, Updates: updates}
	return encodeSwim(swim.Encode(env))
}

// probeableIDsLocked returns the IDs of peers with a live authenticated session
// — the only legitimate direct-ping targets and ping-req relays. The caller
// holds n.mu.
func (n *Node) probeableIDsLocked() []identity.NodeID {
	out := make([]identity.NodeID, 0, len(n.byID))
	for id, p := range n.byID {
		if p.state == StateConnected && p.sess != nil {
			out = append(out, id)
		}
	}
	// Sort before returning: n.byID is a Go map whose range order is randomized,
	// and the detector's seeded Fisher-Yates shuffle only yields a reproducible
	// probe target if its input order is itself reproducible. A stable sort by
	// node ID makes the whole probe sequence deterministic across runs.
	sortNodeIDs(out)
	return out
}

// sortNodeIDs orders node IDs by their raw 32-byte value (NodeID is not an
// ordered type, so a byte comparison stands in).
func sortNodeIDs(ids []identity.NodeID) {
	sort.Slice(ids, func(i, j int) bool {
		return bytes.Compare(ids[i][:], ids[j][:]) < 0
	})
}

func (n *Node) connectedPeersLocked() []*peer {
	out := make([]*peer, 0, len(n.byID))
	for _, p := range n.byID {
		if p.state == StateConnected && p.sess != nil {
			out = append(out, p)
		}
	}
	return out
}

// pickRelays returns up to k connected peers other than target, shuffled with
// the injected RNG for determinism.
func (n *Node) pickRelays(target identity.NodeID, k int) []*peer {
	n.mu.Lock()
	cand := make([]*peer, 0, len(n.byID))
	for id, p := range n.byID {
		if id == target {
			continue
		}
		if p.state == StateConnected && p.sess != nil {
			cand = append(cand, p)
		}
	}
	n.mu.Unlock()
	// Sort into a reproducible order before the seeded shuffle, for the same
	// reason as probeableIDsLocked: the map range order is otherwise randomized.
	sort.Slice(cand, func(i, j int) bool {
		return bytes.Compare(cand[i].nodeID[:], cand[j].nodeID[:]) < 0
	})
	for i := len(cand) - 1; i > 0; i-- {
		j := n.rng.Intn(i + 1)
		cand[i], cand[j] = cand[j], cand[i]
	}
	if len(cand) > k {
		cand = cand[:k]
	}
	return cand
}

// dialHintLocked builds a discovery hint for a gossip-learned Alive member we
// have no live session to, so the existing (deduped, half-open-bounded) dial
// path can try to connect. The caller holds n.mu. Returns ok=false when we are
// already connected, it is self, or the endpoint is unusable.
func (n *Node) dialHintLocked(id identity.NodeID, ep netip.AddrPort) (discovery.PeerHint, bool) {
	if id == n.self.NodeID() || !ep.IsValid() {
		return discovery.PeerHint{}, false
	}
	if p := n.byID[id]; p != nil && p.state == StateConnected {
		return discovery.PeerHint{}, false
	}
	return discovery.PeerHint{
		NodeID:       id.String(),
		Addrs:        []netip.AddrPort{ep},
		ProtoVersion: discovery.ProtoVersion,
	}, true
}

// RosterRow is a status-view row describing a member's gossiped membership plus
// this node's direct-link state to it.
type RosterRow struct {
	NodeID      identity.NodeID
	IsSelf      bool
	Label       string
	State       string
	Incarnation uint64
	Endpoint    netip.AddrPort
	StateChange time.Time
	Linked      bool
}

// RosterSnapshot returns the FULL gossiped roster (every member, not just
// directly-discovered peers) for the status view, read under the same mutex the
// loop mutates under.
func (n *Node) RosterSnapshot() []RosterRow {
	n.mu.RLock()
	defer n.mu.RUnlock()
	rows := n.roster.Rows()
	out := make([]RosterRow, 0, len(rows))
	for _, r := range rows {
		rr := RosterRow{
			NodeID:      r.ID,
			IsSelf:      r.IsSelf,
			State:       r.State.String(),
			Incarnation: r.Incarnation,
			Endpoint:    r.Endpoint,
			StateChange: r.StateChange,
		}
		if r.IsSelf {
			rr.Label = n.self.Label
			rr.Linked = true
		} else if p := n.byID[r.ID]; p != nil {
			rr.Label = p.label
			rr.Linked = p.state == StateConnected && p.sess != nil
		}
		out = append(out, rr)
	}
	return out
}

// MemberState returns the roster state string for a node ID and whether it is
// known, for tests.
func (n *Node) MemberState(id identity.NodeID) (string, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	s, ok := n.roster.State(id)
	if !ok {
		return "", false
	}
	return s.String(), true
}

// MemberIncarnation returns a member's incarnation and whether it is known, for
// tests.
func (n *Node) MemberIncarnation(id identity.NodeID) (uint64, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, r := range n.roster.Rows() {
		if r.ID == id {
			return r.Incarnation, true
		}
	}
	return 0, false
}
