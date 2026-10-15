package session

import "time"

// seg is a contiguous run of stream bytes at an absolute offset, produced by the
// send side for transmission.
type seg struct {
	off  uint64
	data []byte
}

// --- RTT estimation (Karn / Jacobson) --------------------------------------

type rttEstimator struct {
	srtt, rttvar      time.Duration
	has               bool
	initial, min, max time.Duration
	g                 float64 // 1/8
	h                 float64 // 1/4
}

func newRTT(p Params) rttEstimator {
	return rttEstimator{initial: p.InitialRTO, min: p.MinRTO, max: p.MaxRTO, g: 0.125, h: 0.25}
}

func (e *rttEstimator) update(sample time.Duration) {
	if sample <= 0 {
		return
	}
	if !e.has {
		e.srtt = sample
		e.rttvar = sample / 2
		e.has = true
		return
	}
	// RFC 6298 smoothing.
	diff := e.srtt - sample
	if diff < 0 {
		diff = -diff
	}
	e.rttvar = e.rttvar - time.Duration(e.h*float64(e.rttvar)) + time.Duration(e.h*float64(diff))
	e.srtt = e.srtt - time.Duration(e.g*float64(e.srtt)) + time.Duration(e.g*float64(sample))
}

// base returns the current RTO before exponential backoff.
func (e *rttEstimator) base() time.Duration {
	if !e.has {
		return clampDur(e.initial, e.min, e.max)
	}
	rto := e.srtt + 4*e.rttvar
	return clampDur(rto, e.min, e.max)
}

// backoff returns base<<tries, capped at max.
func (e *rttEstimator) backoff(tries int) time.Duration {
	rto := e.base()
	for i := 0; i < tries; i++ {
		rto *= 2
		if rto >= e.max {
			return e.max
		}
	}
	return rto
}

func clampDur(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}

// --- send side --------------------------------------------------------------

// sendStream is one simplex reliable byte-stream (this node -> peer). Bytes
// [sndUna, sndUna+len(out)) are buffered and unacked; [sndUna, sndNxt) have been
// transmitted at least once, [sndNxt, sndUna+len(out)) are queued but unsent.
// On a resume (new epoch) sndNxt is rewound to sndUna so the whole unacked
// window is re-chunked and resent from the exact cumulative-acked offset.
type sendStream struct {
	p      Params
	sndUna uint64
	sndNxt uint64
	out    []byte

	peerRcvWnd uint32

	rtt        rttEstimator
	timerArmed bool
	timerAt    time.Time
	tries      int

	// Karn RTT sampling: time one in-flight segment; discard the sample if that
	// segment was retransmitted.
	sampling    bool
	sampleOff   uint64
	sampleStart time.Time
	sampleRetx  bool

	zwpArmed bool
	zwpAt    time.Time
	zwpTries int

	finOffset *uint64
	finAcked  bool

	lastProgress time.Time
}

func newSendStream(p Params, now time.Time) sendStream {
	return sendStream{p: p, rtt: newRTT(p), peerRcvWnd: p.SendWindow, lastProgress: now}
}

func (s *sendStream) window() uint64 {
	w := uint64(s.peerRcvWnd)
	if sw := uint64(s.p.SendWindow); w > sw {
		w = sw
	}
	return w
}

func (s *sendStream) inflight() uint64 { return s.sndNxt - s.sndUna }

// freeAdmission returns how many more app bytes may be buffered (SendWindow cap).
func (s *sendStream) freeAdmission() int {
	cap := int(s.p.SendWindow) - len(s.out)
	if cap < 0 {
		return 0
	}
	return cap
}

// accept buffers up to freeAdmission bytes of b and returns the count accepted.
func (s *sendStream) accept(b []byte, now time.Time) int {
	n := s.freeAdmission()
	if n > len(b) {
		n = len(b)
	}
	if n <= 0 {
		return 0
	}
	if len(s.out) == 0 {
		s.lastProgress = now
	}
	s.out = append(s.out, b[:n]...)
	return n
}

// fillable returns fresh (never-sent) segments the window permits, advancing
// sndNxt and arming the retransmit timer.
func (s *sendStream) fillable(now time.Time) []seg {
	win := s.window()
	bufEnd := s.sndUna + uint64(len(s.out))
	sendCap := s.sndUna + win // may be below sndNxt if window shrank
	end := bufEnd
	if sendCap < end {
		end = sendCap
	}
	if end <= s.sndNxt {
		return nil
	}
	var segs []seg
	for s.sndNxt < end {
		n := uint64(s.p.MaxChunk)
		if end-s.sndNxt < n {
			n = end - s.sndNxt
		}
		lo := s.sndNxt - s.sndUna
		segs = append(segs, seg{off: s.sndNxt, data: s.out[lo : lo+n]})
		if !s.sampling {
			s.sampling = true
			s.sampleOff = s.sndNxt
			s.sampleStart = now
			s.sampleRetx = false
		}
		s.sndNxt += n
	}
	s.armTimer(now)
	return segs
}

func (s *sendStream) armTimer(now time.Time) {
	if s.timerArmed {
		return
	}
	s.timerArmed = true
	s.tries = 0
	s.timerAt = now.Add(s.rtt.backoff(0))
}

// onAck applies a cumulative ack. It clamps to [sndUna, sndNxt]; an ackOff above
// sndNxt is invalid (would free unsent data) and signals a RESET. Returns
// (progress, invalid).
func (s *sendStream) onAck(ackOff uint64, peerWnd uint32, now time.Time) (bool, bool) {
	if ackOff > s.sndNxt {
		return false, true
	}
	s.peerRcvWnd = peerWnd
	if peerWnd > 0 {
		s.zwpArmed = false
	}
	if ackOff <= s.sndUna {
		return false, false
	}
	drop := ackOff - s.sndUna
	s.out = s.out[drop:]
	if s.sampling && !s.sampleRetx && ackOff > s.sampleOff {
		s.rtt.update(now.Sub(s.sampleStart))
		s.sampling = false
	}
	s.sndUna = ackOff
	s.lastProgress = now
	s.tries = 0
	if s.sndUna == s.sndNxt {
		s.timerArmed = false
	} else {
		s.timerArmed = true
		s.timerAt = now.Add(s.rtt.backoff(0))
	}
	return true, false
}

// rtoDue returns a retransmission of the whole unacked window if the timer has
// expired (go-back-N on timeout; correct, throughput-suboptimal, accepted for
// v0.3). It invalidates the current RTT sample (Karn) and backs off the RTO.
func (s *sendStream) rtoDue(now time.Time) []seg {
	if !s.timerArmed || now.Before(s.timerAt) {
		return nil
	}
	if s.sndUna == s.sndNxt {
		s.timerArmed = false
		return nil
	}
	s.tries++
	s.sampleRetx = true
	s.timerAt = now.Add(s.rtt.backoff(s.tries))
	return s.chunkRange(s.sndUna, s.sndNxt)
}

func (s *sendStream) chunkRange(lo, hi uint64) []seg {
	var segs []seg
	for off := lo; off < hi; {
		n := uint64(s.p.MaxChunk)
		if hi-off < n {
			n = hi - off
		}
		idx := off - s.sndUna
		segs = append(segs, seg{off: off, data: s.out[idx : idx+n]})
		off += n
	}
	return segs
}

// zwpDue returns a one-byte zero-window probe when the peer window is zero and
// data is waiting. This is the guaranteed liveness mechanism against a lost
// window-update ACK (the persist timer).
func (s *sendStream) zwpDue(now time.Time) (seg, bool) {
	if s.window() != 0 || len(s.out) == 0 {
		s.zwpArmed = false
		return seg{}, false
	}
	if !s.zwpArmed {
		s.zwpArmed = true
		s.zwpTries = 0
		s.zwpAt = now.Add(s.p.ZWPInterval)
		return seg{}, false
	}
	if now.Before(s.zwpAt) {
		return seg{}, false
	}
	s.zwpTries++
	back := s.p.ZWPInterval
	for i := 1; i < s.zwpTries; i++ {
		back *= 2
		if back >= s.p.MaxRTO {
			back = s.p.MaxRTO
			break
		}
	}
	s.zwpAt = now.Add(back)
	// Probe the first unacked byte; the peer's ACK reply carries the live window.
	return seg{off: s.sndUna, data: s.out[0:1]}, true
}

// onEpochChange rewinds the sent frontier to the cumulative-acked offset so the
// whole unacked window is re-chunked and resent on the new transport epoch, and
// resets the RTO to initial (a long pause must not leave a tiny stale RTO that
// storms on reconnect).
func (s *sendStream) onEpochChange(now time.Time) {
	s.sndNxt = s.sndUna
	s.tries = 0
	s.timerArmed = false
	s.sampling = false
	s.sampleRetx = false
	s.zwpArmed = false
	s.lastProgress = now
}

// hasOutstanding reports whether sent-but-unacked data exists.
func (s *sendStream) hasOutstanding() bool { return s.sndNxt > s.sndUna }

// --- receive side -----------------------------------------------------------

type orange struct {
	off  uint64
	data []byte
}

// recvStream is one simplex reliable byte-stream (peer -> this node). Delivery is
// byte-indexed, never segment-indexed: incoming ranges are trimmed to >= rcvNxt
// and merged, and bytes are delivered strictly on contiguity at rcvNxt, so a
// retransmitted frame that straddles rcvNxt contributes only its novel suffix
// and a frame re-chunked differently across a resume reassembles correctly.
type recvStream struct {
	p       Params
	rcvNxt  uint64
	appRead uint64
	ooo     []orange
	oooLen  int
	peerFin *uint64

	// instrumentation (test assertions): frames dropped wholly below rcvNxt
	// (duplicates) and the peak out-of-order buffer occupancy.
	dedupCount int
	maxOoo     int
}

func newRecvStream(p Params) recvStream { return recvStream{p: p} }

// advertiseWnd is RecvWindow minus delivered-but-unread bytes (rcvNxt-appRead)
// minus buffered out-of-order bytes, so a slow/stopped app reader applies real
// backpressure.
func (r *recvStream) advertiseWnd() uint32 {
	used := (r.rcvNxt - r.appRead) + uint64(r.oooLen)
	if used >= uint64(r.p.RecvWindow) {
		return 0
	}
	return uint32(uint64(r.p.RecvWindow) - used)
}

// onData ingests one DATA range and returns the newly-contiguous bytes to
// deliver plus whether the frame was a pure duplicate (wholly below rcvNxt),
// which feeds the dedup counter.
func (r *recvStream) onData(off uint64, b []byte) (deliver []byte, dropped bool) {
	end := off + uint64(len(b))
	if end <= r.rcvNxt {
		r.dedupCount++
		return nil, true
	}
	if off < r.rcvNxt {
		b = b[r.rcvNxt-off:]
		off = r.rcvNxt
	}
	// Drop bytes beyond the advertised window horizon (appRead + RecvWindow).
	horizon := r.appRead + uint64(r.p.RecvWindow)
	if off >= horizon {
		return nil, false
	}
	if off+uint64(len(b)) > horizon {
		b = b[:horizon-off]
	}
	if len(b) == 0 {
		return nil, false
	}
	r.addRange(off, b)
	r.enforceSegCap()
	if r.oooLen > r.maxOoo {
		r.maxOoo = r.oooLen
	}
	return r.advance(), false
}

// addRange inserts [off, off+len(data)) storing only novel bytes and coalescing
// adjacent/overlapping ranges, keeping ooo sorted and non-overlapping.
func (r *recvStream) addRange(off uint64, data []byte) {
	end := off + uint64(len(data))
	// Carve the incoming range against existing ranges, keeping only gaps.
	type piece struct {
		off  uint64
		data []byte
	}
	var pieces []piece
	cur := off
	for _, e := range r.ooo {
		eEnd := e.off + uint64(len(e.data))
		if eEnd <= cur || e.off >= end {
			continue
		}
		if e.off > cur {
			gapEnd := e.off
			if gapEnd > end {
				gapEnd = end
			}
			pieces = append(pieces, piece{cur, data[cur-off : gapEnd-off]})
		}
		if eEnd > cur {
			cur = eEnd
		}
		if cur >= end {
			break
		}
	}
	if cur < end {
		pieces = append(pieces, piece{cur, data[cur-off : end-off]})
	}
	for _, pc := range pieces {
		if len(pc.data) == 0 {
			continue
		}
		cp := append([]byte(nil), pc.data...)
		r.ooo = append(r.ooo, orange{off: pc.off, data: cp})
		r.oooLen += len(cp)
	}
	r.sortAndCoalesce()
}

func (r *recvStream) sortAndCoalesce() {
	// Insertion sort by offset (ranges are few and nearly sorted).
	for i := 1; i < len(r.ooo); i++ {
		for j := i; j > 0 && r.ooo[j].off < r.ooo[j-1].off; j-- {
			r.ooo[j], r.ooo[j-1] = r.ooo[j-1], r.ooo[j]
		}
	}
	out := r.ooo[:0]
	for _, e := range r.ooo {
		if len(out) > 0 {
			last := &out[len(out)-1]
			lastEnd := last.off + uint64(len(last.data))
			if e.off <= lastEnd {
				// Overlap/adjacent: append only the novel tail.
				if eEnd := e.off + uint64(len(e.data)); eEnd > lastEnd {
					last.data = append(last.data, e.data[lastEnd-e.off:]...)
				}
				continue
			}
		}
		out = append(out, e)
	}
	r.ooo = out
}

func (r *recvStream) enforceSegCap() {
	for len(r.ooo) > r.p.OooSegCap {
		// Drop the furthest-future range to bound memory and segment count.
		last := r.ooo[len(r.ooo)-1]
		r.oooLen -= len(last.data)
		r.ooo = r.ooo[:len(r.ooo)-1]
	}
}

// advance pops contiguous bytes starting at rcvNxt and returns them.
func (r *recvStream) advance() []byte {
	var out []byte
	for len(r.ooo) > 0 && r.ooo[0].off == r.rcvNxt {
		out = append(out, r.ooo[0].data...)
		r.rcvNxt += uint64(len(r.ooo[0].data))
		r.oooLen -= len(r.ooo[0].data)
		r.ooo = r.ooo[1:]
	}
	return out
}

// onRead advances the app-consumed cursor (freeing receive window).
func (r *recvStream) onRead(n int) { r.appRead += uint64(n) }
