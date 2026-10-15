// Package session is the pure, side-effect-free reliable-stream and durable
// session state machine for DMesh v0.3. Mirroring internal/swim, it contains no
// goroutines, no sockets, and no clock of its own: every method takes the
// current time plus inbound data and returns outbound *actions* (frames to
// seal, bytes to deliver, control signals). All concurrency and I/O live in
// package node, whose single event-loop goroutine owns the sessions and drives
// them. This is what makes `go test -race` trivial and the logic unit-testable
// in isolation, exactly as swim.Roster is.
//
// The layer provides a reliable, ordered, bidirectional, identity-anchored byte
// stream on top of the best-effort Noise transport. It survives the underlying
// transport dropping (and the node roaming / re-handshaking onto a fresh Noise
// epoch) and resumes from the exact byte offset with no loss, no duplication,
// and in-order delivery.
//
// Correctness references (studied, NOT depended on): TCP for cumulative ACK,
// the snd.una/snd.nxt/rcv.nxt cursor model, Karn/Jacobson RTO estimation, the
// persist timer / zero-window probe, and FIN half-close; QUIC for the
// absolute-byte-offset stream abstraction that makes resume-by-identity across
// an epoch change expressible. v0.3 ships correct reliability + flow control
// with a fixed send window and RTO-only loss recovery (no fast-retransmit, no
// SACK); congestion control and SACK are deferred throughput refinements.
package session

import "time"

// Params holds every tunable of the session layer. DefaultParams returns the
// production values; tests tighten the windows and timers so the injectable
// clock drives everything deterministically.
type Params struct {
	// MaxChunk is the largest DATA payload in one frame. It is the transport's
	// MaxPlaintext (1184) minus the 28-byte session+data header
	// (msgSession 1 + subtype 1 + sessionID 16 + offset 8 + len 2), so one DATA
	// frame is always one datagram with no fragmentation.
	MaxChunk int
	// SendWindow bounds the total unacked send buffer (bytes queued but not yet
	// cumulatively acked) per direction. Admission blocks a writer once it would
	// be exceeded, so the send buffer is hard-bounded.
	SendWindow uint32
	// RecvWindow bounds the receive buffer (delivered-but-unread + out-of-order)
	// per direction and is the flow-control window advertised to the peer.
	RecvWindow uint32
	// InitialRTO is the retransmit timeout before any RTT sample exists.
	InitialRTO time.Duration
	// MinRTO / MaxRTO clamp the estimated RTO.
	MinRTO, MaxRTO time.Duration
	// ZWPInterval is the base zero-window-probe (persist timer) interval; it
	// backs off multiplicatively up to MaxRTO.
	ZWPInterval time.Duration
	// PauseThreshold is how long tx may have in-flight data with a non-zero send
	// window and make no ack progress before the transport is judged dropped and
	// the session is paused. It MUST comfortably exceed several RTOs so a merely
	// lossy link keeps recovering on the same epoch rather than being falsely
	// paused.
	PauseThreshold time.Duration
	// Grace is how long a paused session is retained awaiting re-attach before it
	// is torn down with ErrGraceTimeout. It is deliberately >= the SWIM
	// Alive->Dead horizon so "alive-but-unreachable => stay paused" holds; a
	// roster Dead/Left short-circuits teardown earlier.
	Grace time.Duration
	// Linger is the TIME-WAIT duration a cleanly-closed-and-drained session is
	// retained (buffers already freed) to re-answer a retransmitted peer FIN whose
	// FIN_ACK was lost, before it is finally torn down and its slot freed. It is
	// bounded and typically much shorter than Grace.
	Linger time.Duration
	// OooSegCap caps the number of out-of-order byte ranges buffered on receive,
	// in addition to the RecvWindow byte cap.
	OooSegCap int
	// MaxSessionsPerPeer / MaxTotalSessions cap concurrent sessions (enforced by
	// the node before allocation on the inbound OPEN path).
	MaxSessionsPerPeer int
	MaxTotalSessions   int
	// AcceptBacklog bounds the inbound-session accept queue.
	AcceptBacklog int
}

// DefaultParams returns the production session parameters.
func DefaultParams() Params {
	return Params{
		MaxChunk:           1156,
		SendWindow:         256 * 1024,
		RecvWindow:         256 * 1024,
		InitialRTO:         200 * time.Millisecond,
		MinRTO:             50 * time.Millisecond,
		MaxRTO:             10 * time.Second,
		ZWPInterval:        1 * time.Second,
		PauseThreshold:     3 * time.Second,
		Grace:              30 * time.Second,
		Linger:             5 * time.Second,
		OooSegCap:          256,
		MaxSessionsPerPeer: 64,
		MaxTotalSessions:   4096,
		AcceptBacklog:      128,
	}
}

// WithDefaults returns a copy of p with every zero-valued field filled from
// DefaultParams. It is applied by session.New to the stream tunables and by the
// node to the session caps/backlog, so a caller may override a single field and
// still get sane values for the rest.
func (p Params) WithDefaults() Params {
	d := DefaultParams()
	if p.MaxChunk == 0 {
		p.MaxChunk = d.MaxChunk
	}
	if p.SendWindow == 0 {
		p.SendWindow = d.SendWindow
	}
	if p.RecvWindow == 0 {
		p.RecvWindow = d.RecvWindow
	}
	if p.InitialRTO == 0 {
		p.InitialRTO = d.InitialRTO
	}
	if p.MinRTO == 0 {
		p.MinRTO = d.MinRTO
	}
	if p.MaxRTO == 0 {
		p.MaxRTO = d.MaxRTO
	}
	if p.ZWPInterval == 0 {
		p.ZWPInterval = d.ZWPInterval
	}
	if p.PauseThreshold == 0 {
		p.PauseThreshold = d.PauseThreshold
	}
	if p.Grace == 0 {
		p.Grace = d.Grace
	}
	if p.Linger == 0 {
		p.Linger = d.Linger
	}
	if p.OooSegCap == 0 {
		p.OooSegCap = d.OooSegCap
	}
	if p.MaxSessionsPerPeer == 0 {
		p.MaxSessionsPerPeer = d.MaxSessionsPerPeer
	}
	if p.MaxTotalSessions == 0 {
		p.MaxTotalSessions = d.MaxTotalSessions
	}
	if p.AcceptBacklog == 0 {
		p.AcceptBacklog = d.AcceptBacklog
	}
	return p
}
