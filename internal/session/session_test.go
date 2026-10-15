package session

import (
	"bytes"
	"math/rand"
	"testing"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
)

// twoway is a pure in-memory simulator of two sessions exchanging frames over a
// lossy / reordering / duplicating link, driven entirely by a logical clock. No
// goroutines, no sockets: it is the pure analogue of the node sim.
type twoway struct {
	t    *testing.T
	a, b *Session
	now  time.Time
	rng  *rand.Rand

	lossPermille int
	reorder      bool
	dup          bool
	epoch        uint64

	// in-flight frames toward each side (reorder buffer)
	toA, toB []Frame

	recvA, recvB []byte // app-delivered bytes
	eofA, eofB   bool
	dropped      int // frames dropped as pure duplicates at the receiver
	buffered     int // max ooo bytes observed on either side
}

func newTwoway(t *testing.T, seed int64, p Params) *twoway {
	now := time.Unix(1700000000, 0)
	idA := idOf(1)
	idB := idOf(2)
	sid, _ := NewSessionID()
	w := &twoway{
		t:   t,
		now: now,
		rng: rand.New(rand.NewSource(seed)),
	}
	w.a = New(sid, idB, p, now)
	w.b = New(sid, idA, p, now)
	// Bind epoch 1 on both and open.
	w.epoch = 1
	w.a.OnTransportReady(1, now)
	w.b.OnTransportReady(1, now)
	w.route(w.a.Start(now), true)
	return w
}

func idOf(b byte) identity.NodeID {
	var n identity.NodeID
	n[0] = b
	n[31] = b
	return n
}

// route enqueues an action's frames toward the peer and records deliveries.
func (w *twoway) route(a Action, fromA bool) {
	if fromA {
		w.recvA = append(w.recvA, a.Deliver...)
		w.a.rx.onRead(len(a.Deliver)) // app consumes immediately in the sim
		if a.EOF {
			w.eofA = true
		}
	} else {
		w.recvB = append(w.recvB, a.Deliver...)
		w.b.rx.onRead(len(a.Deliver))
		if a.EOF {
			w.eofB = true
		}
	}
	for _, f := range a.Frames {
		if fromA {
			w.toB = append(w.toB, f)
		} else {
			w.toA = append(w.toA, f)
		}
	}
}

func (w *twoway) deliverPending() {
	// Apply chaos then deliver everything currently queued, routing replies.
	toA := w.drain(&w.toA)
	toB := w.drain(&w.toB)
	for _, f := range toB {
		w.route(w.b.OnFrame(f, w.now), false)
		if n := w.b.RecvBuffered(); n > w.buffered {
			w.buffered = n
		}
	}
	for _, f := range toA {
		w.route(w.a.OnFrame(f, w.now), true)
		if n := w.a.RecvBuffered(); n > w.buffered {
			w.buffered = n
		}
	}
}

// drain applies loss / reorder / dup to a queue and returns frames to deliver.
func (w *twoway) drain(q *[]Frame) []Frame {
	src := *q
	*q = nil
	var out []Frame
	for _, f := range src {
		if w.lossPermille > 0 && w.rng.Intn(1000) < w.lossPermille {
			continue // lost
		}
		out = append(out, f)
		if w.dup && w.rng.Intn(100) < 20 {
			out = append(out, f) // duplicate
		}
	}
	if w.reorder && len(out) > 1 {
		w.rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	}
	// Count pure-duplicate DATA that the receiver will drop below rcvNxt, for the
	// dedup assertion. (Approximate: real count comes from the receiver.)
	return out
}

func (w *twoway) tick() {
	w.route(w.a.OnTick(w.now, RosterAlive, true, true), true)
	w.route(w.b.OnTick(w.now, RosterAlive, true, true), false)
}

func (w *twoway) advance(d time.Duration) { w.now = w.now.Add(d) }

// run pumps until both deliver fully or a step budget is exhausted.
func (w *twoway) run(maxSteps int) {
	for i := 0; i < maxSteps; i++ {
		w.deliverPending()
		w.advance(60 * time.Millisecond)
		w.tick()
		if len(w.toA) == 0 && len(w.toB) == 0 &&
			!w.a.tx.hasOutstanding() && !w.b.tx.hasOutstanding() &&
			len(w.a.tx.out) == 0 && len(w.b.tx.out) == 0 {
			// one more delivery round to flush trailing acks/fins
			w.deliverPending()
			w.advance(60 * time.Millisecond)
			w.tick()
			w.deliverPending()
			return
		}
	}
}

func TestBulkTransferClean(t *testing.T) {
	p := tpBig()
	w := newTwoway(t, 1, p)
	payload := bytes.Repeat([]byte("The quick brown fox. "), 50) // ~1050 bytes
	writeAll(t, w, w.a, payload, true)
	w.a.CloseWrite(w.now)
	w.run(5000)
	if !bytes.Equal(w.recvB, payload) {
		t.Fatalf("payload mismatch: got %d bytes want %d", len(w.recvB), len(payload))
	}
	if !w.eofB {
		t.Fatalf("no EOF at receiver")
	}
}

func TestBulkTransferUnderLossAndReorder(t *testing.T) {
	p := tpBig()
	w := newTwoway(t, 7, p)
	w.lossPermille = 200
	w.reorder = true
	w.dup = true
	payload := bytes.Repeat([]byte("abcdefghij"), 120) // 1200 bytes
	writeAll(t, w, w.a, payload, true)
	w.a.CloseWrite(w.now)
	w.run(200000)
	if !bytes.Equal(w.recvB, payload) {
		t.Fatalf("payload mismatch under loss: got %d want %d", len(w.recvB), len(payload))
	}
	if w.buffered == 0 {
		t.Fatalf("expected out-of-order buffering to occur (reorder path not exercised)")
	}
}

func TestBidirectional(t *testing.T) {
	p := tpBig()
	w := newTwoway(t, 3, p)
	w.lossPermille = 100
	w.reorder = true
	pa := bytes.Repeat([]byte("A->B "), 100)
	pb := bytes.Repeat([]byte("B->A "), 100)
	writeAll(t, w, w.a, pa, true)
	writeAll(t, w, w.b, pb, false)
	w.a.CloseWrite(w.now)
	w.b.CloseWrite(w.now)
	w.run(200000)
	if !bytes.Equal(w.recvB, pa) {
		t.Fatalf("A->B mismatch: %d vs %d", len(w.recvB), len(pa))
	}
	if !bytes.Equal(w.recvA, pb) {
		t.Fatalf("B->A mismatch: %d vs %d", len(w.recvA), len(pb))
	}
}

// TestResumeAcrossEpochChange drives a transfer, forces a new epoch mid-stream
// (as a roam/re-handshake would), and asserts the stream resumes byte-exact with
// a positive resume count.
func TestResumeAcrossEpochChange(t *testing.T) {
	p := tpBig()
	w := newTwoway(t, 11, p)
	payload := bytes.Repeat([]byte("RESUME-"), 200) // 1400 bytes
	writeAll(t, w, w.a, payload, true)
	// Partially deliver.
	for i := 0; i < 5; i++ {
		w.deliverPending()
		w.advance(60 * time.Millisecond)
		w.tick()
	}
	midA := w.a.ResumeCount()
	// Simulate a transport epoch change on both sides (drop in-flight frames, new
	// Noise epoch), exactly as handleSessReady -> OnTransportReady does.
	w.toA = nil
	w.toB = nil
	w.epoch++
	w.route(w.a.OnTransportReady(w.epoch, w.now), true)
	w.route(w.b.OnTransportReady(w.epoch, w.now), false)
	if w.a.ResumeCount() <= midA {
		t.Fatalf("resume count did not increase: %d", w.a.ResumeCount())
	}
	w.a.CloseWrite(w.now)
	w.run(200000)
	if !bytes.Equal(w.recvB, payload) {
		t.Fatalf("resume payload mismatch: got %d want %d", len(w.recvB), len(payload))
	}
	if !w.eofB {
		t.Fatalf("no EOF after resume")
	}
}

// TestResumeRechunked proves byte-level (not segment-keyed) reassembly: the data
// is re-chunked with a different MaxChunk across the resume.
func TestResumeRechunked(t *testing.T) {
	p := tpBig()
	w := newTwoway(t, 13, p)
	payload := bytes.Repeat([]byte("0123456789"), 100)
	writeAll(t, w, w.a, payload, true)
	for i := 0; i < 4; i++ {
		w.deliverPending()
		w.advance(60 * time.Millisecond)
		w.tick()
	}
	// Re-chunk differently on the sender after the epoch change.
	w.a.p.MaxChunk = 7
	w.a.tx.p.MaxChunk = 7
	w.toA, w.toB = nil, nil
	w.epoch++
	w.route(w.a.OnTransportReady(w.epoch, w.now), true)
	w.route(w.b.OnTransportReady(w.epoch, w.now), false)
	w.a.CloseWrite(w.now)
	w.run(200000)
	if !bytes.Equal(w.recvB, payload) {
		t.Fatalf("rechunked resume mismatch: got %d want %d", len(w.recvB), len(payload))
	}
}

func TestFinHalfClose(t *testing.T) {
	p := tpBig()
	w := newTwoway(t, 5, p)
	payload := []byte("short message")
	writeAll(t, w, w.a, payload, true)
	w.a.CloseWrite(w.now)
	w.run(5000)
	if !bytes.Equal(w.recvB, payload) || !w.eofB {
		t.Fatalf("fin half-close failed: got=%q eof=%v", w.recvB, w.eofB)
	}
	if *w.a.tx.finOffset != uint64(len(payload)) {
		t.Fatalf("fin offset=%d want %d", *w.a.tx.finOffset, len(payload))
	}
}

// TestResumeCursorRejectsRewind witnesses Sec1/Sec3: a stale RESUME/ACK that
// would rewind the cursor or a FIN that would truncate is rejected.
func TestStaleControlFrameRejected(t *testing.T) {
	now := time.Unix(0, 0)
	p := tp()
	var sid SessionID
	sid[0] = 9
	s := New(sid, idOf(8), p, now)
	s.OnTransportReady(1, now)
	s.OnFrame(Frame{Sub: subOpen, Session: s.id, WinHint: p.RecvWindow}, now)
	// Receive some data so rcvNxt advances.
	s.OnFrame(Frame{Sub: subData, Session: s.id, Offset: 0, Data: []byte("0123456789")}, now)
	if s.RcvNxt() != 10 {
		t.Fatalf("rcvNxt=%d", s.RcvNxt())
	}
	// A FIN below rcvNxt must be rejected (no truncation).
	s.OnFrame(Frame{Sub: subFin, Session: s.id, FinOff: 3}, now)
	if s.rx.peerFin != nil {
		t.Fatalf("truncating FIN accepted")
	}
	// Send some data, then a stale ACK below sndUna must not rewind.
	s.Write([]byte("hello"), now)
	s.OnFrame(Frame{Sub: subAck, Session: s.id, AckOff: 5, RcvWnd: p.RecvWindow}, now)
	una := s.SndUna()
	s.OnFrame(Frame{Sub: subAck, Session: s.id, AckOff: 2, RcvWnd: p.RecvWindow}, now)
	if s.SndUna() != una {
		t.Fatalf("stale ack rewound sndUna %d -> %d", una, s.SndUna())
	}
}

// TestIdempotentOpen witnesses Sec2: a duplicated/replayed OPEN for an existing
// session re-acks but never reinitializes cursors or buffers.
func TestIdempotentOpen(t *testing.T) {
	now := time.Unix(0, 0)
	p := tp()
	var sid SessionID
	sid[0] = 1
	// Responder side: created on first OPEN.
	s := New(sid, idOf(2), p, now)
	s.OnTransportReady(1, now)
	s.OnFrame(Frame{Sub: subOpen, Session: sid, WinHint: p.RecvWindow}, now)
	// Receive some data to advance rcvNxt.
	s.OnFrame(Frame{Sub: subData, Session: sid, Offset: 0, Data: []byte("0123456789")}, now)
	if s.RcvNxt() != 10 {
		t.Fatalf("rcvNxt=%d", s.RcvNxt())
	}
	// A replayed OPEN must NOT reset rcvNxt.
	s.OnFrame(Frame{Sub: subOpen, Session: sid, WinHint: p.RecvWindow}, now)
	if s.RcvNxt() != 10 {
		t.Fatalf("replayed OPEN reset rcvNxt to %d", s.RcvNxt())
	}
	if s.State() != StateEstablished {
		t.Fatalf("state=%v", s.State())
	}
}

// TestProperty fuzzes random loss/reorder/dup op sequences and asserts the
// delivered stream is always a byte-exact prefix of the sent stream and
// non-decreasing in length (no dup, no loss, in-order).
func TestProperty(t *testing.T) {
	for seed := int64(0); seed < 40; seed++ {
		p := tpBig()
		w := newTwoway(t, seed, p)
		w.lossPermille = int(50 + seed*7%300)
		w.reorder = seed%2 == 0
		w.dup = seed%3 == 0
		n := 200 + int(seed*37%1500)
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte('A' + (i % 26))
		}
		writeAll(t, w, w.a, payload, true)
		w.a.CloseWrite(w.now)
		// Check prefix invariant incrementally.
		prev := 0
		for i := 0; i < 400000; i++ {
			w.deliverPending()
			if len(w.recvB) < prev {
				t.Fatalf("seed %d: delivered length shrank %d -> %d", seed, prev, len(w.recvB))
			}
			prev = len(w.recvB)
			if !bytes.Equal(w.recvB, payload[:len(w.recvB)]) {
				t.Fatalf("seed %d: delivered not a prefix of sent at len %d", seed, len(w.recvB))
			}
			if len(w.recvB) == len(payload) && w.eofB {
				break
			}
			w.advance(60 * time.Millisecond)
			w.tick()
		}
		if !bytes.Equal(w.recvB, payload) {
			t.Fatalf("seed %d: incomplete: got %d want %d", seed, len(w.recvB), len(payload))
		}
	}
}

// writeAll feeds the whole payload into a session, respecting send-window
// backpressure by pumping the link when the window is full.
func writeAll(t *testing.T, w *twoway, s *Session, payload []byte, fromA bool) {
	t.Helper()
	off := 0
	for off < len(payload) {
		n, a := s.Write(payload[off:], w.now)
		w.route(a, fromA)
		off += n
		if n == 0 {
			// window full: pump to free it
			w.deliverPending()
			w.advance(60 * time.Millisecond)
			w.tick()
		}
	}
}
