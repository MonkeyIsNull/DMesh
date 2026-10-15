package node

import (
	"context"
	"net/netip"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
	"github.com/MonkeyIsNull/DMesh/internal/session"
	"github.com/MonkeyIsNull/DMesh/internal/swim"
	"github.com/MonkeyIsNull/DMesh/internal/transport"
)

// session_loop.go wires the pure session core into the single-owner event loop.
// All durable-session state (the session engines, the per-peer index, the bound
// epoch per identity) is touched ONLY by the loop goroutine; the renderer mutex
// (n.mu) additionally guards the per-session read buffer and the occupancy /
// status accessors, exactly as the roster is guarded. Every session send is a
// direct Seal through the peer's CURRENT loop-owned transport session, resolved
// by identity on each send so a roam/re-handshake that rebinds byID[peer]
// automatically retargets in-flight data to the new Noise epoch.

// liveSession wraps a pure session.Session with the node-side app plumbing: the
// in-order read-delivery buffer (n.mu-guarded), the done/wake signals to parked
// Read/Write calls, and the terminal error.
type liveSession struct {
	s      *session.Session
	peer   identity.NodeID
	handle *Session

	readBuf []byte // n.mu-guarded: delivered-but-unread bytes (== rcvNxt-appRead)
	eof     bool   // n.mu-guarded
	closed  bool   // n.mu-guarded
	err     error  // n.mu-guarded

	// test-only accounting of bytes drained by the read-ack accessor (the
	// production handle's Read owns consumption; these are unused in prod).
	totalRead int    // n.mu-guarded
	consumed  []byte // n.mu-guarded

	done      chan struct{}
	readWake  chan struct{}
	writeWake chan struct{}
}

type sessInbound struct {
	fromID   identity.NodeID
	fromAddr netip.AddrPort
	body     []byte
}

type ctlKind int

const (
	ctlOpen ctlKind = iota
	ctlWrite
	ctlCloseWrite
	ctlClose
	ctlReadAck
	ctlStatus
)

type sessCtlReq struct {
	kind  ctlKind
	peer  identity.NodeID
	id    session.SessionID
	data  []byte
	n     int
	reply chan sessCtlResp // nil for fire-and-forget (readAck)
}

type sessCtlResp struct {
	handle *Session
	n      int
	err    error
	status SessionStatus
}

// --- production tick driver -------------------------------------------------

// runSessionTicks fires the periodic session driver on the injectable clock. It
// only signals the loop; all session work happens in the loop.
func (n *Node) runSessionTicks(ctx context.Context) {
	defer n.wg.Done()
	t := n.clk.NewTimer(n.sessionTickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C():
			n.sbAdd()
			select {
			case n.sessTick <- struct{}{}:
			case <-ctx.Done():
				n.sbDone()
				return
			}
			t.Reset(n.sessionTickInterval)
		}
	}
}

// InjectSessionTick delivers one session tick to the loop. It is used by the
// deterministic harness in place of the tick-timer goroutine; the tick is
// counted so settle() blocks until the loop has fully processed it and every
// cascading reaction (seals, teardown, re-dial).
func (n *Node) InjectSessionTick(ctx context.Context) {
	n.sbAdd()
	select {
	case n.sessTick <- struct{}{}:
	case <-ctx.Done():
		n.sbDone()
	}
}

// --- loop handlers ----------------------------------------------------------

func (n *Node) handleSessTick() {
	now := n.clk.Now()
	// Snapshot the session set: applyAction may delete entries (teardown).
	list := make([]*liveSession, 0, len(n.sessions))
	for _, ls := range n.sessions {
		list = append(list, ls)
	}
	for _, ls := range list {
		if n.isClosed(ls) {
			continue
		}
		rs, known := n.rosterStateFor(ls.peer)
		alive := n.transportAlive(ls.peer)
		a := ls.s.OnTick(now, rs, known, alive)
		n.applyAction(ls, a, now)
	}
}

func (n *Node) handleSessIn(in sessInbound) {
	f, ok := session.Decode(in.body)
	if !ok {
		return
	}
	now := n.clk.Now()
	ls := n.sessions[f.Session]
	if ls == nil {
		// A frame for an unknown session only ever creates one via OPEN, and the
		// created session is bound to the authenticated sender identity — so an
		// OPEN can never manufacture a session owned by anyone but its sender.
		if !f.IsOpen() {
			return
		}
		if !n.admitInboundSession(in.fromID) {
			n.sealSessionFrame(in.fromID, session.ResetFrame(f.Session, session.ResetProtocol))
			return
		}
		ls = n.newLiveSession(f.Session, in.fromID, now)
		// Bind the current transport epoch for this identity.
		ep := n.sessEpoch[in.fromID]
		if ep == 0 {
			ep = 1
			n.setSessEpoch(in.fromID, 1)
		}
		ls.s.OnTransportReady(ep, now)
		// Offer to the app (bounded backlog). A slow Accept cannot grow memory: the
		// session already counts against the caps and the backlog is bounded.
		select {
		case n.accept <- ls.handle:
		default:
			n.sealSessionFrame(in.fromID, session.ResetFrame(f.Session, session.ResetClosed))
			n.teardownSession(ls, session.ErrClosed)
			return
		}
	}
	// Identity guard (Sec5): accept a frame for session S only if it arrived on a
	// transport authenticated as S.peer, checked BEFORE any state mutation. A
	// different credentialed peer handshakes under its own identity, so its frames
	// can never match another peer's session.peer. Applies to every sub-type
	// including RESET.
	if ls.peer != in.fromID {
		return
	}
	a := ls.s.OnFrame(f, now)
	n.applyAction(ls, a, now)
}

func (n *Node) handleSessCtl(req sessCtlReq) {
	now := n.clk.Now()
	switch req.kind {
	case ctlOpen:
		n.openSessionLocked(req, now)
	case ctlWrite:
		ls := n.sessions[req.id]
		if ls == nil || n.isClosed(ls) {
			n.ctlReply(req, sessCtlResp{err: session.ErrClosed})
			return
		}
		acc, a := ls.s.Write(req.data, now)
		n.applyAction(ls, a, now)
		n.ctlReply(req, sessCtlResp{n: acc})
	case ctlCloseWrite:
		ls := n.sessions[req.id]
		if ls == nil || n.isClosed(ls) {
			n.ctlReply(req, sessCtlResp{err: session.ErrClosed})
			return
		}
		a := ls.s.CloseWrite(now)
		n.applyAction(ls, a, now)
		n.ctlReply(req, sessCtlResp{})
	case ctlClose:
		ls := n.sessions[req.id]
		if ls == nil || n.isClosed(ls) {
			n.ctlReply(req, sessCtlResp{})
			return
		}
		a := ls.s.Close(now)
		n.applyAction(ls, a, now)
		n.ctlReply(req, sessCtlResp{})
	case ctlReadAck:
		ls := n.sessions[req.id]
		if ls == nil || n.isClosed(ls) {
			return
		}
		a := ls.s.OnRead(req.n, now)
		n.applyAction(ls, a, now)
	case ctlStatus:
		ls := n.sessions[req.id]
		if ls == nil {
			n.ctlReply(req, sessCtlResp{status: SessionStatus{State: "closed"}})
			return
		}
		n.ctlReply(req, sessCtlResp{status: SessionStatus{
			State:  ls.s.State().String(),
			SndUna: ls.s.SndUna(),
			RcvNxt: ls.s.RcvNxt(),
		}})
	}
}

// openSessionLocked creates the opener side of a session and emits OPEN. If no
// transport to the peer exists yet it kicks a dial; OPEN is (re)transmitted by
// OnTick once the transport binds.
func (n *Node) openSessionLocked(req sessCtlReq, now time.Time) {
	if _, exists := n.sessions[req.id]; exists {
		n.ctlReply(req, sessCtlResp{err: session.ErrClosed})
		return
	}
	if !n.admitInboundSession(req.peer) {
		n.ctlReply(req, sessCtlResp{err: errTooManySessions})
		return
	}
	ls := n.newLiveSession(req.id, req.peer, now)
	ep := n.sessEpoch[req.peer]
	if ep > 0 {
		ls.s.OnTransportReady(ep, now)
	}
	a := ls.s.Start(now)
	n.applyAction(ls, a, now)
	if ep == 0 || !n.transportAlive(req.peer) {
		n.redialSession(req.peer)
	}
	n.ctlReply(req, sessCtlResp{handle: ls.handle})
}

// --- action application -----------------------------------------------------

// applyAction performs the I/O a pure step requested: seal outbound frames
// through the peer's CURRENT transport, deliver received bytes to the read
// buffer, signal parked Read/Write, drive the forced re-dial, and tear the
// session down on termination.
func (n *Node) applyAction(ls *liveSession, a session.Action, now time.Time) {
	for _, f := range a.Frames {
		n.sealSessionFrame(ls.peer, f)
	}
	if len(a.Deliver) > 0 {
		n.mu.Lock()
		ls.readBuf = append(ls.readBuf, a.Deliver...)
		n.mu.Unlock()
		signal(ls.readWake)
	}
	if a.EOF {
		n.mu.Lock()
		ls.eof = true
		n.mu.Unlock()
		signal(ls.readWake)
	}
	// Nudge a parked writer only when send-buffer room actually opened (an ack /
	// resume advanced sndUna). Signaling unconditionally would spin a blocked
	// Write in a tight retry loop against a still-full window.
	if a.WindowFreed {
		signal(ls.writeWake)
	}
	if a.WantReDial {
		n.redialSession(ls.peer)
	}
	if a.Terminated {
		n.teardownSession(ls, a.Err)
	}
}

// sealSessionFrame seals and sends one session frame through the peer's current
// transport, resolved by identity (never a cached pointer). If no live transport
// exists (paused / re-dialing) the frame is dropped; OnTick re-emits it (RTO /
// RESUME retransmit) once the transport returns.
func (n *Node) sealSessionFrame(peer identity.NodeID, f session.Frame) {
	n.mu.RLock()
	p := n.byID[peer]
	var sess *transport.Session
	var addr netip.AddrPort
	if p != nil {
		sess = p.sess
		addr = p.addr
	}
	n.mu.RUnlock()
	if sess == nil {
		return
	}
	n.sealSend(addr, sess, encodeSession(session.Encode(f)))
}

// --- registry helpers (all mutate under n.mu for the renderer/accessors) ----

func (n *Node) newLiveSession(id session.SessionID, peer identity.NodeID, now time.Time) *liveSession {
	ls := &liveSession{
		s:         session.New(id, peer, n.sessParams, now),
		peer:      peer,
		done:      make(chan struct{}),
		readWake:  make(chan struct{}, 1),
		writeWake: make(chan struct{}, 1),
	}
	ls.handle = &Session{node: n, id: id, peer: peer, ls: ls}
	n.mu.Lock()
	n.sessions[id] = ls
	set := n.sessByPeer[peer]
	if set == nil {
		set = make(map[session.SessionID]struct{})
		n.sessByPeer[peer] = set
	}
	set[id] = struct{}{}
	n.mu.Unlock()
	return ls
}

func (n *Node) teardownSession(ls *liveSession, err error) {
	n.mu.Lock()
	if ls.closed {
		n.mu.Unlock()
		return
	}
	ls.closed = true
	ls.err = err
	delete(n.sessions, ls.s.ID())
	if set := n.sessByPeer[ls.peer]; set != nil {
		delete(set, ls.s.ID())
		if len(set) == 0 {
			delete(n.sessByPeer, ls.peer)
		}
	}
	n.mu.Unlock()
	close(ls.done)
	signal(ls.readWake)
	signal(ls.writeWake)
}

func (n *Node) setSessEpoch(peer identity.NodeID, ep uint64) {
	n.mu.Lock()
	n.sessEpoch[peer] = ep
	n.mu.Unlock()
}

// admitInboundSession enforces the per-peer and total session caps. Caller is in
// the loop.
func (n *Node) admitInboundSession(peer identity.NodeID) bool {
	if len(n.sessions) >= n.sessParams.MaxTotalSessions {
		return false
	}
	if set := n.sessByPeer[peer]; set != nil && len(set) >= n.sessParams.MaxSessionsPerPeer {
		return false
	}
	return true
}

func (n *Node) isClosed(ls *liveSession) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return ls.closed
}

func (n *Node) ctlReply(req sessCtlReq, resp sessCtlResp) {
	if req.reply != nil {
		req.reply <- resp
	}
}

// --- roster / transport oracles ---------------------------------------------

func (n *Node) rosterStateFor(peer identity.NodeID) (session.RosterState, bool) {
	n.mu.RLock()
	st, ok := n.roster.State(peer)
	n.mu.RUnlock()
	if !ok {
		return session.RosterDead, false
	}
	switch st {
	case swim.StateAlive:
		return session.RosterAlive, true
	case swim.StateSuspect:
		return session.RosterSuspect, true
	case swim.StateDead:
		return session.RosterDead, true
	case swim.StateLeft:
		return session.RosterLeft, true
	default:
		return session.RosterDead, true
	}
}

func (n *Node) transportAlive(peer identity.NodeID) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	p := n.byID[peer]
	return p != nil && p.sess != nil && p.state == StateConnected
}

func (n *Node) peerEndpointLocked(peer identity.NodeID) (netip.AddrPort, string) {
	if p := n.byID[peer]; p != nil && p.addr.IsValid() {
		return p.addr, p.label
	}
	for _, r := range n.roster.Rows() {
		if r.ID == peer && r.Endpoint.IsValid() {
			return r.Endpoint, ""
		}
	}
	return netip.AddrPort{}, ""
}

// --- forced re-dial ---------------------------------------------------------

// redialSession re-initiates a Noise handshake to a paused session's peer by
// identity, at its last-known endpoint. It is self-throttling: a dial in
// progress (byAddr entry present) or an already-connected transport is a no-op,
// so OnTick can safely request a re-dial every tick while paused.
func (n *Node) redialSession(peer identity.NodeID) {
	n.mu.Lock()
	if p := n.byID[peer]; p != nil && (p.state == StateHandshaking || p.state == StateConnected) {
		n.mu.Unlock()
		return
	}
	ep, label := n.peerEndpointLocked(peer)
	busy := n.byAddr[ep] != nil
	n.mu.Unlock()
	if !ep.IsValid() || busy {
		return
	}
	n.startInitiator(n.runCtx, ep, peer, label)
}

// --- resume hook (called from handleSessReady) ------------------------------

// resumeSessions binds a freshly-(re)connected transport epoch to every session
// anchored to that identity. Because OnTransportReady no-ops on an unchanged
// epoch, a transient same-epoch heal produces no RESUME; a real re-handshake
// bumps the epoch and drives the resume reconciliation. Re-attach is
// authenticated for free: peerID came from a completed Noise handshake, so only
// the real peer can bind a session whose anchor matches.
func (n *Node) resumeSessions(peer identity.NodeID, now time.Time) {
	set := n.sessByPeer[peer]
	if len(set) == 0 {
		// Still advance the epoch counter so a session opened later binds a fresh
		// epoch rather than reusing a stale one.
		n.setSessEpoch(peer, n.sessEpoch[peer]+1)
		return
	}
	ids := make([]session.SessionID, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	n.setSessEpoch(peer, n.sessEpoch[peer]+1)
	ep := n.sessEpoch[peer]
	for _, id := range ids {
		ls := n.sessions[id]
		if ls == nil || n.isClosed(ls) {
			continue
		}
		a := ls.s.OnTransportReady(ep, now)
		n.applyAction(ls, a, now)
	}
}

// signal does a non-blocking send on a cap-1 wake channel.
func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
