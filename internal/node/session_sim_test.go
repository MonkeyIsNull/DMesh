package node

import (
	"bytes"
	"crypto/sha256"
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
	"github.com/MonkeyIsNull/DMesh/internal/session"
)

// session_sim_test.go is the deterministic, offline, loopback-free node-level
// proof of the v0.3 durable-session layer. It reuses the v0.2 in-memory router +
// happens-before barrier + Fake clock, adding transport drop / reconnect / roam
// injection. go test -race must be clean.

// --- session test params ----------------------------------------------------

func testSessionParams() session.Params {
	p := session.DefaultParams()
	p.MaxChunk = 256
	p.SendWindow = 4096
	p.RecvWindow = 1 << 16
	p.InitialRTO = 100 * time.Millisecond
	p.MinRTO = 50 * time.Millisecond
	p.MaxRTO = 2 * time.Second
	p.PauseThreshold = 2 * time.Second // > several RTOs so loss alone never pauses
	p.Grace = 20 * time.Second
	p.ZWPInterval = 300 * time.Millisecond
	return p
}

// newSessionMesh builds an n-node mesh wired for durable sessions (manual ticks,
// manual phases) and connects it.
func newSessionMesh(t *testing.T, seed int64, n int, sp session.Params) *simMesh {
	m := newSimMesh(t, seed)
	for i := 0; i < n; i++ {
		m.addNode(t, "", func(cfg *Config) {
			cfg.SessionParams = sp
			cfg.ManualSessionTick = true
		})
	}
	m.wireFullMesh()
	if !m.waitAllConnected(30 * time.Second) {
		t.Fatal("mesh did not connect")
	}
	return m
}

// transfer feeds payload from `from` to `to` over session id, interleaving
// writes (respecting send-window backpressure) with session ticks, until the
// receiver has delivered the whole payload or the round budget is exhausted.
func (m *simMesh) transfer(from, to *simNode, id session.SessionID, payload []byte, tick time.Duration, maxRounds int) bool {
	return m.finishTransfer(from, to, id, payload, 0, tick, maxRounds)
}

// finishTransfer continues feeding payload from byte offset `off` (the bytes
// below off are already in the session's send buffer / delivered) until the
// receiver has the whole payload. Used after a resume, where the first off bytes
// were already written before the drop.
func (m *simMesh) finishTransfer(from, to *simNode, id session.SessionID, payload []byte, off int, tick time.Duration, maxRounds int) bool {
	for r := 0; r < maxRounds; r++ {
		for off < len(payload) {
			acc := from.n.writeForTest(m.ctx, id, payload[off:])
			if acc == 0 {
				break
			}
			off += acc
		}
		m.r.settle()
		if len(to.n.deliveredForTest(id)) >= len(payload) {
			return true
		}
		m.clk.Advance(tick)
		m.r.settle()
		m.sessTickAll()
		if len(to.n.deliveredForTest(id)) >= len(payload) {
			return true
		}
	}
	return len(to.n.deliveredForTest(id)) >= len(payload)
}

func makePayload(n int, seed int64) []byte {
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	r.Read(b)
	return b
}

// acceptSession drains one inbound session from a node (settling between polls).
func (m *simMesh) acceptSession(sn *simNode, timeout time.Duration) *Session {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case h := <-sn.n.Accept():
			return h
		default:
		}
		m.r.settle()
		time.Sleep(2 * time.Millisecond)
	}
	select {
	case h := <-sn.n.Accept():
		return h
	default:
		return nil
	}
}

// --- 1. bulk transfer under loss: byte-exact, dedup + ooo exercised ---------

func TestSessionBulkUnderLoss(t *testing.T) {
	sp := testSessionParams()
	m := newSessionMesh(t, 1, 2, sp)
	defer m.stop()
	a, b := m.nodes[0], m.nodes[1]

	h, err := a.n.OpenSession(m.ctx, b.id.NodeID())
	if err != nil {
		t.Fatal(err)
	}
	id := h.ID()
	if bs := m.acceptSession(b, 5*time.Second); bs == nil {
		t.Fatal("receiver did not accept session")
	}
	m.r.setLoss(150) // 15% loss; go-back-N retransmit yields reorder + duplicates

	payload := makePayload(6000, 42)
	if !m.transfer(a, b, id, payload, 60*time.Millisecond, 4000) {
		t.Fatalf("transfer incomplete: got %d/%d", len(b.n.deliveredForTest(id)), len(payload))
	}
	got := b.n.deliveredForTest(id)
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch under loss")
	}
	if sha256.Sum256(got) != sha256.Sum256(payload) {
		t.Fatal("sha256 mismatch")
	}
	// Regression guard: the dedup + reassembly code actually ran.
	if d := b.n.dedupCountForTest(id); d == 0 {
		t.Fatal("expected dedup drops > 0 under loss (dedup path not exercised)")
	}
	if o := b.n.maxOooForTest(id); o == 0 {
		t.Fatal("expected out-of-order buffering > 0 under loss (reassembly not exercised)")
	}
}

// --- 2. mid-stream drop -> pause -> reconnect -> RESUME from exact offset ----

func TestSessionMidStreamDropResume(t *testing.T) {
	sp := testSessionParams()
	m := newSessionMesh(t, 2, 2, sp)
	defer m.stop()
	a, b := m.nodes[0], m.nodes[1]

	h, err := a.n.OpenSession(m.ctx, b.id.NodeID())
	if err != nil {
		t.Fatal(err)
	}
	id := h.ID()
	if m.acceptSession(b, 5*time.Second) == nil {
		t.Fatal("no accept")
	}
	payload := makePayload(24000, 7)

	// Deliver a bounded PREFIX cleanly so the resumed session starts from a
	// non-zero, below-total offset. Capping what we WRITE before the drop (rather
	// than relying on how much a settle happens to drain) keeps "partial delivery"
	// deterministic under -race: we never write past prefixBytes, so pre-drop
	// delivery can never reach the full payload. The remaining payload is written
	// AFTER the drop (below), which is what puts unacked data in flight and arms
	// the stall detector.
	const prefixBytes = 8000 // < len(payload); a few SendWindows (4096) wide
	off := 0
	for round := 0; round < 12 && len(b.n.deliveredForTest(id)) < prefixBytes; round++ {
		for off < prefixBytes {
			acc := a.n.writeForTest(m.ctx, id, payload[off:prefixBytes])
			if acc == 0 {
				break
			}
			off += acc
		}
		m.clk.Advance(60 * time.Millisecond)
		m.r.settle()
		m.sessTickAll()
	}
	deliveredBefore := len(b.n.deliveredForTest(id))
	if deliveredBefore == 0 || deliveredBefore >= len(payload) {
		t.Fatalf("want partial delivery before drop, got %d/%d", deliveredBefore, len(payload))
	}
	epochBefore := a.n.boundEpochForTest(id)

	// Drop the transport mid-stream, THEN push a burst so there is unacked,
	// in-flight data vanishing into the blackhole (the trigger for the stall
	// detector). Drive ticks past PauseThreshold -> Paused.
	m.dropTransport(a, b)
	for off < len(payload) {
		acc := a.n.writeForTest(m.ctx, id, payload[off:])
		if acc == 0 {
			break
		}
		off += acc
	}
	m.r.settle()                        // frames seal into the dropped link and are lost
	m.sessPump(600*time.Millisecond, 8) // > PauseThreshold (2s)
	if st := a.n.sessionStateForTest(id); st != session.StatePaused {
		t.Fatalf("sender session not paused after drop: %v", st)
	}

	// Reconnect: retire the dead transport records on both sides (as a real roam
	// does when the old socket's flows die) and re-handshake -> a NEW Noise epoch
	// -> RESUME reconciliation. Keep the SAME addresses: eviction clears the stale
	// records so the re-handshake is clean.
	b.n.evictPeerForTest(a.id.NodeID())
	a.n.evictPeerForTest(b.id.NodeID())
	m.healTransport(a, b)
	m.hint(a, b)
	m.hint(b, a)
	if !m.waitAllConnected(30 * time.Second) {
		t.Fatal("did not reconnect after drop")
	}

	// Finish the transfer over the resumed session (continue from where writing
	// left off; the bytes below `off` are already buffered/resent by the session).
	if !m.finishTransfer(a, b, id, payload, off, 60*time.Millisecond, 4000) {
		t.Fatalf("resume transfer incomplete: %d/%d", len(b.n.deliveredForTest(id)), len(payload))
	}

	// Positive resume assertions.
	if rc := a.n.resumeCountForTest(id); rc == 0 {
		t.Fatal("expected a resume reconciliation (resumeCount>0)")
	}
	if ep := a.n.boundEpochForTest(id); ep <= epochBefore {
		t.Fatalf("bound epoch did not advance across resume: %d <= %d", ep, epochBefore)
	}
	got := b.n.deliveredForTest(id)
	if !bytes.Equal(got, payload) {
		t.Fatalf("resumed payload not byte-exact: %d/%d", len(got), len(payload))
	}
	if b.n.dedupCountForTest(id) < 0 {
		t.Fatal("impossible")
	}
}

// --- 3. peer roams (new endpoint) -> resume by identity ---------------------

func TestSessionRoamResume(t *testing.T) {
	sp := testSessionParams()
	m := newSessionMesh(t, 3, 2, sp)
	defer m.stop()
	a, b := m.nodes[0], m.nodes[1]

	h, err := a.n.OpenSession(m.ctx, b.id.NodeID())
	if err != nil {
		t.Fatal(err)
	}
	id := h.ID()
	if m.acceptSession(b, 5*time.Second) == nil {
		t.Fatal("no accept")
	}
	payload := makePayload(24000, 99)

	off := 0
	for i := 0; i < 2; i++ {
		for off < len(payload) {
			acc := a.n.writeForTest(m.ctx, id, payload[off:])
			if acc == 0 {
				break
			}
			off += acc
		}
		m.clk.Advance(60 * time.Millisecond)
		m.r.settle()
		m.sessTickAll()
	}
	if len(b.n.deliveredForTest(id)) == 0 {
		t.Fatal("no partial delivery before roam")
	}
	epochBefore := a.n.boundEpochForTest(id)

	// B roams to a brand-new address, keeping its *Node + session registry.
	newAddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 9, 2}), 9000)
	b.n.evictPeerForTest(a.id.NodeID())
	a.n.evictPeerForTest(b.id.NodeID())
	m.rebindConn(b, newAddr)
	m.hint(a, b) // A learns B's NEW address
	m.hint(b, a)
	if !m.waitAllConnected(30 * time.Second) {
		t.Fatal("did not reconnect after roam")
	}
	if !m.finishTransfer(a, b, id, payload, off, 60*time.Millisecond, 4000) {
		t.Fatalf("roam transfer incomplete: %d/%d", len(b.n.deliveredForTest(id)), len(payload))
	}
	if a.n.resumeCountForTest(id) == 0 {
		t.Fatal("expected resume after roam")
	}
	if a.n.boundEpochForTest(id) <= epochBefore {
		t.Fatal("epoch did not advance after roam")
	}
	if !bytes.Equal(b.n.deliveredForTest(id), payload) {
		t.Fatal("roamed payload not byte-exact")
	}
}

// --- 4. grace timeout -> teardown surfaced ----------------------------------

func TestSessionGraceTimeout(t *testing.T) {
	sp := testSessionParams()
	sp.Grace = 5 * time.Second
	m := newSessionMesh(t, 4, 2, sp)
	defer m.stop()
	a, b := m.nodes[0], m.nodes[1]

	h, err := a.n.OpenSession(m.ctx, b.id.NodeID())
	if err != nil {
		t.Fatal(err)
	}
	id := h.ID()
	if m.acceptSession(b, 5*time.Second) == nil {
		t.Fatal("no accept")
	}
	// Drop first, THEN push data so there is unacked in-flight work vanishing into
	// the blackhole (the stall trigger). Keep the roster Alive (no SWIM periods),
	// so grace (not SWIM-dead) is what fires.
	m.dropTransport(a, b)
	a.n.writeForTest(m.ctx, id, makePayload(3000, 1))
	m.r.settle()
	m.sessPump(1*time.Second, 10) // past PauseThreshold + Grace (2s + 5s)

	if err := h.errForTest(); err != session.ErrGraceTimeout {
		t.Fatalf("want ErrGraceTimeout, got %v (closed=%v)", err, h.closedForTest())
	}
	if !h.closedForTest() {
		t.Fatal("session not torn down after grace")
	}
	if n := h.sendBufferedForTest(); n != 0 {
		t.Fatalf("send buffer not freed on teardown: %d", n)
	}
}

// --- 5. SWIM declares peer dead -> teardown before grace --------------------

func TestSessionSwimDeadTeardown(t *testing.T) {
	sp := testSessionParams()
	sp.Grace = 10 * time.Minute // grace must NOT be what tears this down
	m := newSessionMesh(t, 5, 2, sp)
	defer m.stop()
	a, b := m.nodes[0], m.nodes[1]

	h, err := a.n.OpenSession(m.ctx, b.id.NodeID())
	if err != nil {
		t.Fatal(err)
	}
	id := h.ID()
	if m.acceptSession(b, 5*time.Second) == nil {
		t.Fatal("no accept")
	}
	a.n.writeForTest(m.ctx, id, makePayload(2000, 1))
	m.clk.Advance(60 * time.Millisecond)
	m.r.settle()
	m.sessTickAll()

	// Isolate B entirely so SWIM suspects then declares it Dead.
	m.r.isolate(b.addr, true)
	for i := 0; i < 40; i++ {
		m.period()
		m.sessTickAll()
		if st, ok := a.n.MemberState(b.id.NodeID()); ok && st == "dead" {
			break
		}
	}
	if st, _ := a.n.MemberState(b.id.NodeID()); st != "dead" {
		t.Fatalf("SWIM did not mark peer dead (state %q)", st)
	}
	// One more tick to let the session observe the Dead roster state.
	m.sessTickAll()
	if err := h.errForTest(); err != session.ErrPeerGone {
		t.Fatalf("want ErrPeerGone on SWIM-dead, got %v", err)
	}
	if n := h.sendBufferedForTest(); n != 0 {
		t.Fatalf("buffers not freed on SWIM-dead teardown: %d", n)
	}
}

// --- 6. flow control bounds buffers; drain resumes --------------------------

func TestSessionFlowControl(t *testing.T) {
	sp := testSessionParams()
	sp.SendWindow = 2048
	sp.RecvWindow = 2048
	m := newSessionMesh(t, 6, 2, sp)
	defer m.stop()
	a, b := m.nodes[0], m.nodes[1]

	h, err := a.n.OpenSession(m.ctx, b.id.NodeID())
	if err != nil {
		t.Fatal(err)
	}
	id := h.ID()
	if m.acceptSession(b, 5*time.Second) == nil {
		t.Fatal("no accept")
	}
	payload := makePayload(20000, 3) // far exceeds the windows

	// Receiver deliberately never reads. Feed + pump; the sender must stall with
	// bounded buffers, never growing without bound.
	off := 0
	maxSend, maxRecv := 0, 0
	for i := 0; i < 200; i++ {
		for off < len(payload) {
			acc := a.n.writeForTest(m.ctx, id, payload[off:])
			if acc == 0 {
				break
			}
			off += acc
		}
		m.clk.Advance(100 * time.Millisecond)
		m.r.settle()
		m.sessTickAll()
		if s := a.n.sendBufferedForTest(id); s > maxSend {
			maxSend = s
		}
		if rb := b.n.readBufLenForTest(id); rb > maxRecv {
			maxRecv = rb
		}
	}
	if maxSend > int(sp.SendWindow) {
		t.Fatalf("send buffer exceeded window: %d > %d", maxSend, sp.SendWindow)
	}
	if maxRecv > int(sp.RecvWindow) {
		t.Fatalf("recv buffer exceeded window: %d > %d", maxRecv, sp.RecvWindow)
	}
	// The receive buffer should have actually filled (backpressure engaged).
	if maxRecv < int(sp.RecvWindow)/2 {
		t.Fatalf("recv buffer never filled; flow control not exercised (%d)", maxRecv)
	}

	// Now drain on the receiver (app reads), reopening the window. The transfer
	// must complete, exercising the zero-window-probe / window-update path.
	for i := 0; i < 4000; i++ {
		b.n.drainReadForTest(m.ctx, id)
		m.r.settle()
		for off < len(payload) {
			acc := a.n.writeForTest(m.ctx, id, payload[off:])
			if acc == 0 {
				break
			}
			off += acc
		}
		m.clk.Advance(100 * time.Millisecond)
		m.r.settle()
		m.sessTickAll()
		if b.n.totalReadForTest(id) >= len(payload) {
			break
		}
	}
	// Drain any residual delivered bytes.
	for b.n.readBufLenForTest(id) > 0 {
		b.n.drainReadForTest(m.ctx, id)
		m.r.settle()
	}
	if got := b.n.totalReadForTest(id); got != len(payload) {
		t.Fatalf("flow-controlled transfer incomplete after drain: %d/%d", got, len(payload))
	}
	if !bytes.Equal(b.n.allReadForTest(id), payload) {
		t.Fatal("flow-controlled payload not byte-exact")
	}
}

// --- 7. bidirectional streaming ---------------------------------------------

func TestSessionBidirectional(t *testing.T) {
	sp := testSessionParams()
	m := newSessionMesh(t, 7, 2, sp)
	defer m.stop()
	a, b := m.nodes[0], m.nodes[1]

	ha, err := a.n.OpenSession(m.ctx, b.id.NodeID())
	if err != nil {
		t.Fatal(err)
	}
	idA := ha.ID()
	hb := m.acceptSession(b, 5*time.Second)
	if hb == nil {
		t.Fatal("no accept")
	}
	// B opens a second, independent session back to A.
	hbOut, err := b.n.OpenSession(m.ctx, a.id.NodeID())
	if err != nil {
		t.Fatal(err)
	}
	idB := hbOut.ID()
	if m.acceptSession(a, 5*time.Second) == nil {
		t.Fatal("no accept of reverse session")
	}
	m.r.setLoss(80)

	pa := makePayload(5000, 11)
	pb := makePayload(5000, 22)
	// Interleave both directions.
	offA, offB := 0, 0
	for r := 0; r < 6000; r++ {
		for offA < len(pa) {
			acc := a.n.writeForTest(m.ctx, idA, pa[offA:])
			if acc == 0 {
				break
			}
			offA += acc
		}
		for offB < len(pb) {
			acc := b.n.writeForTest(m.ctx, idB, pb[offB:])
			if acc == 0 {
				break
			}
			offB += acc
		}
		m.r.settle()
		doneA := len(b.n.deliveredForTest(idA)) >= len(pa)
		doneB := len(a.n.deliveredForTest(idB)) >= len(pb)
		if doneA && doneB {
			break
		}
		m.clk.Advance(60 * time.Millisecond)
		m.r.settle()
		m.sessTickAll()
	}
	if !bytes.Equal(b.n.deliveredForTest(idA), pa) {
		t.Fatalf("A->B mismatch: %d/%d", len(b.n.deliveredForTest(idA)), len(pa))
	}
	if !bytes.Equal(a.n.deliveredForTest(idB), pb) {
		t.Fatalf("B->A mismatch: %d/%d", len(a.n.deliveredForTest(idB)), len(pb))
	}
}

// --- 8. no hijack: a credentialed third party cannot touch another pair's
// session ---------------------------------------------------------------------

func TestSessionNoHijack(t *testing.T) {
	sp := testSessionParams()
	m := newSessionMesh(t, 8, 3, sp)
	defer m.stop()
	a, b, c := m.nodes[0], m.nodes[1], m.nodes[2]

	h, err := a.n.OpenSession(m.ctx, b.id.NodeID())
	if err != nil {
		t.Fatal(err)
	}
	id := h.ID()
	if m.acceptSession(b, 5*time.Second) == nil {
		t.Fatal("no accept")
	}
	payload := makePayload(3000, 5)

	// C (a fully credentialed mesh member) forges DATA / RESET for A and B's
	// sessionID. The forged frames are injected INTO B's node tagged as arriving
	// from C's authenticated transport (i.e. as if C handshook with B and sent
	// them) — the only shape a real hijack could take. B's session for `id` is
	// anchored to A, so the identity guard (ls.peer != in.fromID) must drop every
	// one of C's frames BEFORE any state mutation. Injecting into C's own node (as
	// an earlier version did) exercised nothing: C owns no such session.
	m.r.settle() // park B's loop so the baseline reads of loop-owned session state are race-free (quiescence precondition)
	rcvBefore := b.n.rcvNxtForTest(id)
	stateBefore := b.n.sessionStateForTest(id)
	b.n.injectSessionFrameForTest(m.ctx, c.id.NodeID(), session.Frame{Sub: 3 /*subData*/, Session: id, Offset: 0, Data: []byte("HIJACK")})
	b.n.injectSessionFrameForTest(m.ctx, c.id.NodeID(), session.ResetFrame(id, session.ResetClosed))
	m.r.settle()
	m.sessTickAll()
	m.r.settle()

	if b.n.sessionClosedForTest(id) {
		t.Fatal("forged RESET from a third party tore the session down (hijack)")
	}
	if b.n.rcvNxtForTest(id) != rcvBefore {
		t.Fatal("forged DATA from a third party advanced the receive cursor (hijack)")
	}
	if st := b.n.sessionStateForTest(id); st != stateBefore {
		t.Fatalf("forged frames from a third party perturbed session state: %v -> %v", stateBefore, st)
	}
	// The legitimate transfer still completes.
	if !m.transfer(a, b, id, payload, 60*time.Millisecond, 4000) {
		t.Fatalf("legit transfer broken after hijack attempt")
	}
	if !bytes.Equal(b.n.deliveredForTest(id), payload) {
		t.Fatal("payload corrupted after hijack attempt")
	}
}

// --- 8b. clean bidirectional close reaches a terminal state and frees slots --

// TestSessionCleanCloseTerminates proves the hero's resource-bounding guarantee:
// after a bulk transfer completes and BOTH directions are half-closed and
// drained, each side enters the TIME-WAIT linger with its buffers freed, and
// OnTick tears it down after the linger — freeing the n.sessions slot (so it no
// longer counts against MaxTotalSessions) and firing Done()/Err(). A session that
// stayed StateEstablished forever (the pre-fix bug) would fail the terminal-state
// and freed-slot assertions.
func TestSessionCleanCloseTerminates(t *testing.T) {
	sp := testSessionParams()
	sp.Linger = 3 * time.Second
	m := newSessionMesh(t, 21, 2, sp)
	defer m.stop()
	a, b := m.nodes[0], m.nodes[1]

	h, err := a.n.OpenSession(m.ctx, b.id.NodeID())
	if err != nil {
		t.Fatal(err)
	}
	id := h.ID()
	bh := m.acceptSession(b, 5*time.Second)
	if bh == nil {
		t.Fatal("no accept")
	}

	payload := makePayload(8000, 77)
	if !m.transfer(a, b, id, payload, 60*time.Millisecond, 4000) {
		t.Fatalf("transfer incomplete: %d/%d", len(b.n.deliveredForTest(id)), len(payload))
	}
	if got := b.n.deliveredForTest(id); !bytes.Equal(got, payload) {
		t.Fatalf("payload not byte-exact before close: %d/%d", len(got), len(payload))
	}

	// Both sides half-close. The receiver's (empty) FIN completes the clean
	// bidirectional close on the sender; the sender's FIN_ACK completes it on the
	// receiver. One settle carries the whole FIN/FIN_ACK cascade on a healthy link.
	a.n.closeWriteForTest(m.ctx, id)
	m.r.settle()
	b.n.closeWriteForTest(m.ctx, id)
	m.r.settle()
	m.sessTickAll()

	// Both sessions are now in TIME-WAIT with their send buffers freed.
	for _, sn := range []*simNode{a, b} {
		if st := sn.n.sessionStateForTest(id); st != session.StateClosing {
			t.Fatalf("expected StateClosing after clean close, got %v", st)
		}
		if sb := sn.n.sendBufferedForTest(id); sb != 0 {
			t.Fatalf("send buffer not freed in TIME-WAIT: %d", sb)
		}
	}

	// Advance past the linger: OnTick tears both sessions down, freeing the slot.
	m.sessPump(1*time.Second, 5) // > Linger (3s)

	for _, sn := range []*simNode{a, b} {
		if !sn.n.sessionClosedForTest(id) {
			t.Fatalf("session not torn down after linger (still occupies a slot)")
		}
		if n := sn.n.liveSessionForTest(id); n != nil {
			t.Fatalf("session still present in registry after linger")
		}
	}
	// The app observes a clean terminal close via Done()/Err() on both handles.
	for _, hh := range []*Session{h, bh} {
		select {
		case <-hh.Done():
		default:
			t.Fatal("Done() not closed after clean termination")
		}
		if e := hh.errForTest(); e != session.ErrClosed {
			t.Fatalf("want ErrClosed on clean termination, got %v", e)
		}
		if !hh.closedForTest() {
			t.Fatal("handle not marked closed after clean termination")
		}
	}
}

// --- 8c. bulk transfer under loss + duplication: byte-exact, dedup exercised -

// TestSessionBulkUnderLossAndDup drives a bulk transfer through a router that
// both drops AND duplicates packets, proving byte-exact in-order delivery with
// the receiver's dedup path exercised by genuine on-wire duplicates (not only the
// go-back-N retransmits of the loss-only test).
func TestSessionBulkUnderLossAndDup(t *testing.T) {
	sp := testSessionParams()
	m := newSessionMesh(t, 22, 2, sp)
	defer m.stop()
	a, b := m.nodes[0], m.nodes[1]

	h, err := a.n.OpenSession(m.ctx, b.id.NodeID())
	if err != nil {
		t.Fatal(err)
	}
	id := h.ID()
	if m.acceptSession(b, 5*time.Second) == nil {
		t.Fatal("no accept")
	}
	m.r.setLoss(100) // 10% loss
	m.r.setDup(150)  // 15% of delivered packets arrive twice

	payload := makePayload(6000, 123)
	if !m.transfer(a, b, id, payload, 60*time.Millisecond, 6000) {
		t.Fatalf("transfer incomplete: %d/%d", len(b.n.deliveredForTest(id)), len(payload))
	}
	got := b.n.deliveredForTest(id)
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch under loss+dup")
	}
	if sha256.Sum256(got) != sha256.Sum256(payload) {
		t.Fatal("sha256 mismatch under loss+dup")
	}
	// Prove duplicates were actually injected on the wire (so the receiver's
	// carve/coalesce dedup in recvStream.addRange was exercised) — byte-exactness
	// above is the proof it tolerated them with no loss/dup/reorder of delivery.
	// (dedupCount counts only wholly-below-rcvNxt drops, which on-wire dups that
	// land beside their in-flight original do not produce, so it is not asserted.)
	if m.r.dupSentCount() == 0 {
		t.Fatal("router injected no duplicates; dup path not exercised")
	}
}

// --- 9. leak / teardown: parked Read + Write unblock, no goroutine leak ------

func TestSessionLeakTeardown(t *testing.T) {
	sp := testSessionParams()
	sp.SendWindow = 1024
	sp.Grace = 3 * time.Second
	m := newSessionMesh(t, 9, 2, sp)
	defer m.stop()
	a, b := m.nodes[0], m.nodes[1]

	h, err := a.n.OpenSession(m.ctx, b.id.NodeID())
	if err != nil {
		t.Fatal(err)
	}
	id := h.ID()
	bh := m.acceptSession(b, 5*time.Second)
	if bh == nil {
		t.Fatal("no accept")
	}

	_ = bh
	before := goroutineCount()

	// Drop FIRST so the write cannot drain (otherwise the handle's Write would
	// flood the barrier while data flows through the real read loops and settle()
	// could not reach quiescence). Both parked calls are on the SENDER's handle:
	// its session is the one that stall-pauses and then grace-tears-down, so a
	// parked Read (nothing inbound) and a window-blocked Write both ride the same
	// teardown.
	m.dropTransport(a, b)
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := h.Read(buf) // A never receives; blocks until teardown
		readErr <- err
	}()
	writeErr := make(chan error, 1)
	go func() {
		// Far more than the send window; fills the window once (into the blackhole)
		// then parks until teardown.
		_, err := h.Write(makePayload(100000, 1))
		writeErr <- err
	}()
	time.Sleep(100 * time.Millisecond) // let both park (quiescent: no barrier activity)

	// Let grace expire -> teardown. Both parked calls must unblock.
	m.sessPump(1*time.Second, 8)

	select {
	case <-readErr:
	case <-time.After(3 * time.Second):
		t.Fatal("parked Read did not unblock on teardown")
	}
	select {
	case <-writeErr:
	case <-time.After(3 * time.Second):
		t.Fatal("parked Write did not unblock on teardown")
	}
	if !a.n.sessionClosedForTest(id) {
		t.Fatal("sender session not torn down")
	}
	after := goroutineCount()
	if after > before+2 {
		t.Fatalf("goroutine leak: before=%d after=%d", before, after)
	}
}

// --- test accessors (called only when the mesh is quiesced) -----------------
//
// QUIESCENCE PRECONDITION (important): several accessors below read the
// loop-owned pure session (ls.s) — SendBuffered, ResumeCount, Epoch, State,
// RcvNxt, DedupCount, MaxOoo. The loop mutates ls.s from OnTick/OnFrame WITHOUT
// holding n.mu, so the n.mu.RLock some of these take does NOT actually guard
// ls.s; it only guards the n.sessions map lookup and the n.mu-guarded liveSession
// fields (readBuf/closed/err/...). These reads are race-free ONLY because every
// caller invokes them after settle() has parked the loop at quiescence, so there
// is no temporal overlap with the owner. Do NOT call them off the quiescence
// path; if that is ever needed, route the read through the loop (a ctlStatus-style
// request) so the owner performs it.

func (n *Node) liveSessionForTest(id session.SessionID) *liveSession {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.sessions[id]
}

// Handle-based accessors read terminal state AFTER teardown (when the session is
// gone from n.sessions but the app still holds the handle), mirroring how a real
// app observes Err()/Done().
func (s *Session) errForTest() error {
	s.node.mu.RLock()
	defer s.node.mu.RUnlock()
	return s.ls.err
}

func (s *Session) closedForTest() bool {
	s.node.mu.RLock()
	defer s.node.mu.RUnlock()
	return s.ls.closed
}

func (s *Session) sendBufferedForTest() int { return s.ls.s.SendBuffered() }

func (n *Node) writeForTest(ctx interface{ Done() <-chan struct{} }, id session.SessionID, data []byte) int {
	reply := make(chan sessCtlResp, 1)
	n.sbAdd()
	select {
	case n.sessCtl <- sessCtlReq{kind: ctlWrite, id: id, data: data, reply: reply}:
	case <-ctx.Done():
		n.sbDone()
		return 0
	}
	resp := <-reply
	return resp.n
}

func (n *Node) closeWriteForTest(ctx interface{ Done() <-chan struct{} }, id session.SessionID) {
	reply := make(chan sessCtlResp, 1)
	n.sbAdd()
	select {
	case n.sessCtl <- sessCtlReq{kind: ctlCloseWrite, id: id, reply: reply}:
	case <-ctx.Done():
		n.sbDone()
		return
	}
	<-reply
}

func (n *Node) drainReadForTest(ctx interface{ Done() <-chan struct{} }, id session.SessionID) int {
	n.mu.Lock()
	ls := n.sessions[id]
	if ls == nil {
		n.mu.Unlock()
		return 0
	}
	k := len(ls.readBuf)
	if k > 0 {
		ls.totalRead += k
		ls.consumed = append(ls.consumed, ls.readBuf...)
		ls.readBuf = ls.readBuf[:0]
	}
	n.mu.Unlock()
	if k > 0 {
		n.sbAdd()
		select {
		case n.sessCtl <- sessCtlReq{kind: ctlReadAck, id: id, n: k}:
		case <-ctx.Done():
			n.sbDone()
		}
	}
	return k
}

func (n *Node) deliveredForTest(id session.SessionID) []byte {
	n.mu.RLock()
	defer n.mu.RUnlock()
	ls := n.sessions[id]
	if ls == nil {
		return nil
	}
	return append([]byte(nil), ls.readBuf...)
}

func (n *Node) injectSessionFrameForTest(ctx interface{ Done() <-chan struct{} }, from identity.NodeID, f session.Frame) {
	// Deliver as if it arrived authenticated from `from` over its transport.
	n.sbAdd()
	select {
	case n.sessIn <- sessInbound{fromID: from, body: session.Encode(f)}:
	case <-ctx.Done():
		n.sbDone()
	}
}

func (n *Node) resumeCountForTest(id session.SessionID) uint64 {
	ls := n.liveSessionForTest(id)
	if ls == nil {
		return 0
	}
	return ls.s.ResumeCount()
}

func (n *Node) boundEpochForTest(id session.SessionID) uint64 {
	ls := n.liveSessionForTest(id)
	if ls == nil {
		return 0
	}
	return ls.s.Epoch()
}

func (n *Node) sessionStateForTest(id session.SessionID) session.State {
	ls := n.liveSessionForTest(id)
	if ls == nil {
		return session.StateDead
	}
	return ls.s.State()
}

func (n *Node) sessionErrForTest(id session.SessionID) error {
	n.mu.RLock()
	defer n.mu.RUnlock()
	ls := n.sessions[id]
	if ls == nil {
		return nil
	}
	return ls.err
}

func (n *Node) sessionClosedForTest(id session.SessionID) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	ls := n.sessions[id]
	return ls == nil || ls.closed
}

func (n *Node) sendBufferedForTest(id session.SessionID) int {
	ls := n.liveSessionForTest(id)
	if ls == nil {
		return 0
	}
	return ls.s.SendBuffered()
}

func (n *Node) readBufLenForTest(id session.SessionID) int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	ls := n.sessions[id]
	if ls == nil {
		return 0
	}
	return len(ls.readBuf)
}

func (n *Node) totalReadForTest(id session.SessionID) int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	ls := n.sessions[id]
	if ls == nil {
		return 0
	}
	return ls.totalRead + len(ls.readBuf)
}

func (n *Node) allReadForTest(id session.SessionID) []byte {
	n.mu.RLock()
	defer n.mu.RUnlock()
	ls := n.sessions[id]
	if ls == nil {
		return nil
	}
	out := make([]byte, 0, ls.totalRead+len(ls.readBuf))
	out = append(out, ls.consumed...)
	out = append(out, ls.readBuf...)
	return out
}

func (n *Node) dedupCountForTest(id session.SessionID) int {
	ls := n.liveSessionForTest(id)
	if ls == nil {
		return 0
	}
	return ls.s.DedupCount()
}

func (n *Node) maxOooForTest(id session.SessionID) int {
	ls := n.liveSessionForTest(id)
	if ls == nil {
		return 0
	}
	return ls.s.MaxOoo()
}

func (n *Node) rcvNxtForTest(id session.SessionID) uint64 {
	ls := n.liveSessionForTest(id)
	if ls == nil {
		return 0
	}
	return ls.s.RcvNxt()
}

// evictPeerForTest retires all transport records for a peer identity (canceling
// any driver), simulating a roam where the OS tears down the old socket's flows.
// It preserves the durable-session registry (that is the point).
func (n *Node) evictPeerForTest(peer identity.NodeID) {
	n.mu.Lock()
	var cancels []func()
	for addr, p := range n.byAddr {
		if p.nodeID == peer {
			if p.cancel != nil {
				cancels = append(cancels, p.cancel)
			}
			delete(n.byAddr, addr)
			n.half.Remove(addr)
		}
	}
	delete(n.byID, peer)
	n.mu.Unlock()
	for _, c := range cancels {
		c()
	}
}
