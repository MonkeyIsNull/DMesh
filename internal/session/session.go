package session

import (
	"errors"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
)

// State is the durable-session lifecycle state.
type State int

const (
	// StateOpening: OPEN sent (opener) or received (responder), awaiting OPEN_ACK.
	StateOpening State = iota
	// StateEstablished: the reliable stream is live on the current epoch.
	StateEstablished
	// StateResuming: a new transport epoch is bound; RESUME is outstanding and the
	// unacked window is being resent from the cumulative-acked offset.
	StateResuming
	// StatePaused: the transport dropped; the session is retained (buffers + cursors
	// kept) awaiting re-attach within the grace window.
	StatePaused
	// StateClosed: cleanly closed (both FINs) or locally closed.
	StateClosed
	// StateDead: torn down (grace timeout, peer gone, reset).
	StateDead
	// StateClosing: both directions are cleanly half-closed and fully drained
	// (local FIN acked AND peer FIN delivered). The big buffers are freed and the
	// session lingers only to re-answer a retransmitted peer FIN whose FIN_ACK was
	// lost (a TIME-WAIT), then OnTick tears it down after the grace-bounded linger.
	// It is NOT terminal: OnFrame still runs so a retransmitted FIN is re-acked.
	StateClosing
)

func (s State) String() string {
	switch s {
	case StateOpening:
		return "opening"
	case StateEstablished:
		return "established"
	case StateResuming:
		return "resuming"
	case StatePaused:
		return "paused"
	case StateClosed:
		return "closed"
	case StateDead:
		return "dead"
	case StateClosing:
		return "closing"
	default:
		return "unknown"
	}
}

// Terminal reports whether the session has been torn down or closed.
func (s State) Terminal() bool { return s == StateClosed || s == StateDead }

// RosterState mirrors swim.MemberState for the pause/teardown oracle without
// importing swim into the pure core. The node maps swim.State -> these.
type RosterState int

const (
	RosterAlive RosterState = iota
	RosterSuspect
	RosterDead
	RosterLeft
)

// Session errors surfaced to the app via Err().
var (
	ErrPeerGone     = errors.New("session: peer gone")
	ErrGraceTimeout = errors.New("session: grace timeout; transport did not recover")
	ErrClosed       = errors.New("session: closed")
	ErrReset        = errors.New("session: reset by peer")
)

// Action is the set of outbound effects a step produced. The node seals Frames,
// appends Deliver to the read buffer, signals EOF/termination, and acts on the
// re-dial / cancel-epoch requests.
type Action struct {
	Frames  []Frame
	Deliver []byte
	EOF     bool // peer stream fully delivered (FIN reached)

	WantReDial bool

	Terminated bool
	Err        error

	ResumeStarted bool // a resume reconciliation began this step (test seam)
	WindowFreed   bool // send-buffer room opened (an ack/resume advanced sndUna)
}

// Session is the durable, identity-anchored reliable session state machine. It
// is pure: the node owns the loop, the clock, and all I/O.
type Session struct {
	id    SessionID
	peer  identity.NodeID
	p     Params
	state State
	epoch uint64

	tx sendStream
	rx recvStream

	graceEnd          time.Time
	lingerEnd         time.Time // TIME-WAIT deadline once cleanly closed (StateClosing)
	resumeOutstanding bool
	resumeCount       uint64

	pendingOpen bool // opener: OPEN sent, OPEN_ACK not yet seen (tick-retransmit)
	pendingFin  bool // CloseWrite requested; FIN to be sent once data is acked
}

// New builds a session in StateOpening. initiator distinguishes the opener (which
// will send OPEN) from the responder (created on an inbound OPEN).
func New(id SessionID, peer identity.NodeID, p Params, now time.Time) *Session {
	p = p.WithDefaults()
	return &Session{
		id:    id,
		peer:  peer,
		p:     p,
		state: StateOpening,
		tx:    newSendStream(p, now),
		rx:    newRecvStream(p),
	}
}

// ID returns the session id.
func (s *Session) ID() SessionID { return s.id }

// Peer returns the authenticated peer identity this session is anchored to.
func (s *Session) Peer() identity.NodeID { return s.peer }

// State returns the current lifecycle state.
func (s *Session) State() State { return s.state }

// Epoch returns the currently bound transport epoch.
func (s *Session) Epoch() uint64 { return s.epoch }

// ResumeCount returns how many resume reconciliations have occurred (test seam).
func (s *Session) ResumeCount() uint64 { return s.resumeCount }

// SendBuffered returns the unacked send-buffer occupancy in bytes.
func (s *Session) SendBuffered() int { return len(s.tx.out) }

// RecvBuffered returns the out-of-order receive-buffer occupancy in bytes.
func (s *Session) RecvBuffered() int { return s.rx.oooLen }

// DedupCount returns how many wholly-duplicate frames the receiver dropped
// below rcvNxt (test regression guard for the dedup path).
func (s *Session) DedupCount() int { return s.rx.dedupCount }

// MaxOoo returns the peak out-of-order receive-buffer occupancy in bytes (test
// regression guard for the reassembly path).
func (s *Session) MaxOoo() int { return s.rx.maxOoo }

// RcvNxt / SndUna expose cursors for tests and status.
func (s *Session) RcvNxt() uint64 { return s.rx.rcvNxt }
func (s *Session) SndUna() uint64 { return s.tx.sndUna }
func (s *Session) SndNxt() uint64 { return s.tx.sndNxt }

// --- opener bootstrap -------------------------------------------------------

// Start is called by the opener to emit the OPEN frame.
func (s *Session) Start(now time.Time) Action {
	s.tx.lastProgress = now
	s.pendingOpen = true
	return Action{Frames: []Frame{{Sub: subOpen, Session: s.id, WinHint: s.p.RecvWindow}}}
}

// --- app write/close --------------------------------------------------------

// Write buffers app bytes (bounded by SendWindow) and emits any newly-sendable
// frames. It returns the number of bytes accepted; a short accept means the send
// window is full and the caller must retry after window frees.
func (s *Session) Write(b []byte, now time.Time) (int, Action) {
	if s.state.Terminal() {
		return 0, Action{}
	}
	n := s.tx.accept(b, now)
	var a Action
	if s.state == StateEstablished || s.state == StateResuming {
		a.Frames = s.collectData(now)
	}
	return n, a
}

// CloseWrite half-closes the send direction: it records the final offset and the
// FIN is emitted once all data through it is acked.
func (s *Session) CloseWrite(now time.Time) Action {
	if s.state.Terminal() || s.pendingFin {
		return Action{}
	}
	fin := s.tx.sndUna + uint64(len(s.tx.out))
	s.tx.finOffset = &fin
	s.pendingFin = true
	var a Action
	if s.state == StateEstablished || s.state == StateResuming {
		a.Frames = s.collectData(now)
	}
	return a
}

// OnRead advances the app-consumed receive cursor by n (freeing receive
// window) and returns a window-update ACK when the freed window is worth
// announcing (the window was tight / zero), so a stalled sender is unblocked.
func (s *Session) OnRead(n int, now time.Time) Action {
	if n <= 0 || s.state.Terminal() {
		return Action{}
	}
	before := s.rx.advertiseWnd()
	s.rx.onRead(n)
	after := s.rx.advertiseWnd()
	if before < uint32(s.p.MaxChunk) && after >= before {
		return Action{Frames: []Frame{{Sub: subAck, Session: s.id, AckOff: s.rx.rcvNxt, RcvWnd: after}}}
	}
	return Action{}
}

// Close aborts the session locally, emitting a RESET and tearing down.
func (s *Session) Close(now time.Time) Action {
	if s.state.Terminal() {
		return Action{}
	}
	a := Action{Frames: []Frame{{Sub: subReset, Session: s.id, Code: ResetClosed}}}
	s.teardown(StateClosed, ErrClosed, &a)
	return a
}

// --- inbound frames ---------------------------------------------------------

// OnFrame dispatches one decoded session sub-frame.
func (s *Session) OnFrame(f Frame, now time.Time) Action {
	if s.state.Terminal() {
		return Action{}
	}
	// TIME-WAIT: the session is cleanly closed and drained; only re-answer a
	// retransmitted peer FIN (its FIN_ACK was lost) or honor a RESET. Everything
	// else is ignored — the buffers are gone and no cursor may advance.
	if s.state == StateClosing {
		switch f.Sub {
		case subFin:
			return s.onFin(f, now)
		case subReset:
			var a Action
			s.teardown(StateDead, ErrReset, &a)
			return a
		default:
			return Action{}
		}
	}
	switch f.Sub {
	case subOpen:
		return s.onOpen(f, now)
	case subOpenAck:
		return s.onOpenAck(f, now)
	case subData:
		return s.onData(f, now)
	case subAck:
		return s.onAck(f, now)
	case subResume:
		return s.onResume(f, now)
	case subResumeAck:
		return s.onResumeAck(f, now)
	case subFin:
		return s.onFin(f, now)
	case subFinAck:
		return s.onFinAck(f, now)
	case subReset:
		var a Action
		s.teardown(StateDead, ErrReset, &a)
		return a
	default:
		return Action{}
	}
}

func (s *Session) onOpen(f Frame, now time.Time) Action {
	// Idempotent (Sec2): an OPEN for an existing non-terminal session re-sends
	// OPEN_ACK and never reinitializes cursors/buffers.
	if s.tx.peerRcvWnd == s.p.SendWindow && f.WinHint > 0 {
		s.tx.peerRcvWnd = f.WinHint
	}
	if s.state == StateOpening {
		s.state = StateEstablished
	}
	return Action{Frames: []Frame{{Sub: subOpenAck, Session: s.id, WinHint: s.p.RecvWindow}}}
}

func (s *Session) onOpenAck(f Frame, now time.Time) Action {
	if f.WinHint > 0 {
		s.tx.peerRcvWnd = f.WinHint
	}
	s.pendingOpen = false
	if s.state == StateOpening {
		s.state = StateEstablished
	}
	var a Action
	a.Frames = s.collectData(now)
	return a
}

func (s *Session) onData(f Frame, now time.Time) Action {
	deliver, _ := s.rx.onData(f.Offset, f.Data)
	a := Action{Deliver: deliver}
	// Always ack (even a pure duplicate): the ACK carries the live window and is
	// the recovery signal.
	a.Frames = append(a.Frames, Frame{Sub: subAck, Session: s.id, AckOff: s.rx.rcvNxt, RcvWnd: s.rx.advertiseWnd()})
	s.maybeEOF(&a)
	s.maybeClose(now)
	return a
}

func (s *Session) onAck(f Frame, now time.Time) Action {
	progress, invalid := s.tx.onAck(f.AckOff, f.RcvWnd, now)
	if invalid {
		var a Action
		a.Frames = []Frame{{Sub: subReset, Session: s.id, Code: ResetProtocol}}
		s.teardown(StateDead, ErrReset, &a)
		return a
	}
	// Ack progress while paused means the SAME transport recovered (a transient
	// blackhole that healed): un-pause and keep going on the surviving epoch, no
	// resume reconciliation needed.
	if progress && s.state == StatePaused {
		s.state = StateEstablished
		s.graceEnd = time.Time{}
	}
	var a Action
	a.WindowFreed = progress
	a.Frames = s.collectData(now)
	return a
}

func (s *Session) onResume(f Frame, now time.Time) Action {
	// Range-validated cursor apply (Sec1): clamp peerRcvNxt into [sndUna, sndNxt].
	if f.AckOff > s.tx.sndNxt {
		var a Action
		a.Frames = []Frame{{Sub: subReset, Session: s.id, Code: ResetProtocol}}
		s.teardown(StateDead, ErrReset, &a)
		return a
	}
	if f.AckOff > s.tx.sndUna {
		s.tx.out = s.tx.out[f.AckOff-s.tx.sndUna:]
		s.tx.sndUna = f.AckOff
	}
	s.tx.peerRcvWnd = f.RcvWnd
	// Force a full resend of the (now trimmed) unacked window on this epoch; the
	// peer announced a new epoch so anything it has not cumulatively acked must be
	// re-sent. Idempotent and safe to receive repeatedly / while Established.
	s.tx.sndNxt = s.tx.sndUna
	s.tx.tries = 0
	s.tx.timerArmed = false
	s.tx.sampling = false
	s.tx.lastProgress = now
	a := Action{WindowFreed: true, Frames: []Frame{{Sub: subResumeAck, Session: s.id, AckOff: s.rx.rcvNxt, RcvWnd: s.rx.advertiseWnd()}}}
	if s.state == StateEstablished || s.state == StateResuming || s.state == StatePaused {
		if s.state == StatePaused {
			s.state = StateResuming
		}
		a.Frames = append(a.Frames, s.collectData(now)...)
	}
	return a
}

func (s *Session) onResumeAck(f Frame, now time.Time) Action {
	if f.AckOff > s.tx.sndNxt {
		var a Action
		a.Frames = []Frame{{Sub: subReset, Session: s.id, Code: ResetProtocol}}
		s.teardown(StateDead, ErrReset, &a)
		return a
	}
	if f.AckOff > s.tx.sndUna {
		s.tx.out = s.tx.out[f.AckOff-s.tx.sndUna:]
		s.tx.sndUna = f.AckOff
	}
	s.tx.peerRcvWnd = f.RcvWnd
	s.resumeOutstanding = false
	if s.state == StateResuming {
		s.state = StateEstablished
	}
	var a Action
	a.WindowFreed = true
	a.Frames = s.collectData(now)
	return a
}

func (s *Session) onFin(f Frame, now time.Time) Action {
	// Sec3: reject a FIN that would truncate or that contradicts a recorded one.
	if f.FinOff < s.rx.rcvNxt {
		return Action{}
	}
	if s.rx.peerFin != nil && *s.rx.peerFin != f.FinOff {
		return Action{}
	}
	if s.rx.peerFin == nil {
		fin := f.FinOff
		s.rx.peerFin = &fin
	}
	a := Action{Frames: []Frame{{Sub: subFinAck, Session: s.id, FinOff: f.FinOff}}}
	s.maybeEOF(&a)
	s.maybeClose(now)
	return a
}

func (s *Session) onFinAck(f Frame, now time.Time) Action {
	if s.tx.finOffset != nil && f.FinOff == *s.tx.finOffset {
		s.tx.finAcked = true
	}
	s.maybeClose(now)
	return Action{}
}

func (s *Session) maybeEOF(a *Action) {
	if s.rx.peerFin != nil && s.rx.rcvNxt >= *s.rx.peerFin {
		a.EOF = true
	}
}

// completed reports a clean bidirectional close: our FIN has been acked AND the
// peer's FIN has been received with all of its data delivered through finOffset.
func (s *Session) completed() bool {
	return s.pendingFin && s.tx.finAcked &&
		s.rx.peerFin != nil && s.rx.rcvNxt >= *s.rx.peerFin
}

// maybeClose enters the TIME-WAIT linger (StateClosing) once both directions are
// cleanly closed and drained. The send/receive buffers are freed immediately —
// nothing is unacked or undelivered — and the session lingers only to re-answer a
// retransmitted peer FIN whose FIN_ACK was lost; OnTick tears it down after the
// grace-bounded linger so the node frees the slot and fires Done()/Err().
func (s *Session) maybeClose(now time.Time) {
	switch s.state {
	case StateEstablished, StateResuming, StatePaused:
	default:
		return
	}
	if !s.completed() {
		return
	}
	s.state = StateClosing
	linger := s.p.Linger
	if linger > s.p.Grace {
		linger = s.p.Grace
	}
	s.lingerEnd = now.Add(linger)
	s.graceEnd = time.Time{}
	s.tx.out = nil
	s.rx.ooo = nil
	s.rx.oooLen = 0
	s.resumeOutstanding = false
}

// --- periodic tick ----------------------------------------------------------

// OnTick is the periodic driver: retransmits, fresh fills, probes, RESUME
// retransmit, and the stall/pause/grace/teardown state machine tied to the SWIM
// roster. epochAlive reports whether a live transport currently exists for the
// peer identity.
func (s *Session) OnTick(now time.Time, rs RosterState, rsKnown bool, epochAlive bool) Action {
	switch s.state {
	case StateOpening:
		// Opener retransmits OPEN until OPEN_ACK (the responder answers idempotently).
		if s.pendingOpen {
			return Action{Frames: []Frame{{Sub: subOpen, Session: s.id, WinHint: s.p.RecvWindow}}}
		}
		return Action{}
	case StateEstablished, StateResuming:
		var a Action
		// SWIM Dead/Left is the v0.2 payoff: tear the session down immediately and
		// surface it to the app, even when the stream is idle (no in-flight data to
		// stall on). This is the roster-driven teardown §3.5 calls for.
		if rs == RosterDead || rs == RosterLeft {
			s.teardown(StateDead, ErrPeerGone, &a)
			return a
		}
		a.Frames = s.collectData(now)
		if s.resumeOutstanding {
			a.Frames = append(a.Frames, Frame{Sub: subResume, Session: s.id, AckOff: s.rx.rcvNxt, RcvWnd: s.rx.advertiseWnd()})
		}
		// Stall detection: in-flight data with a non-zero send window but no ack
		// progress for PauseThreshold => the transport has dropped (a zero window is
		// flow control, handled by the ZWP, and never a pause). PauseThreshold
		// exceeds several RTOs so a merely lossy link keeps recovering here rather
		// than being falsely paused.
		//
		// Corner case: a drop that coincides with a peer-advertised zero window is
		// NOT caught here (window()==0), so the grace timer never arms and
		// ErrGraceTimeout cannot fire during that stretch; teardown then rests on
		// SWIM marking the peer Dead/Left. Roam/resume is unaffected
		// (OnTransportReady drives resume independently of pause state). A dedicated
		// zero-window liveness check is a deferred refinement.
		stalled := s.tx.sndNxt > s.tx.sndUna && s.tx.window() > 0 &&
			now.Sub(s.tx.lastProgress) >= s.p.PauseThreshold
		if stalled {
			if !rsKnown || rs == RosterDead || rs == RosterLeft {
				s.teardown(StateDead, ErrPeerGone, &a)
				return a
			}
			// Alive/Suspect: PAUSE but keep the buffers, cursors, AND the transport.
			// A blackholed transport's driver stays alive (no read deadline), so the
			// Noise epoch survives: we keep RTO-retransmitting over it, and recovery
			// on heal is a plain same-epoch retransmit (onAck un-pauses). We do NOT
			// cancel the epoch; a genuine new epoch (roam / re-handshake) arrives via
			// handleSessReady -> OnTransportReady and drives the RESUME path instead.
			s.state = StatePaused
			s.graceEnd = now.Add(s.p.Grace)
			if !epochAlive {
				a.WantReDial = true
			}
		}
		return a
	case StatePaused:
		var a Action
		if !rsKnown || rs == RosterDead || rs == RosterLeft {
			s.teardown(StateDead, ErrPeerGone, &a)
			return a
		}
		if !now.Before(s.graceEnd) {
			s.teardown(StateDead, ErrGraceTimeout, &a)
			return a
		}
		// Keep driving the data plane over whatever transport currently exists so a
		// same-epoch heal recovers by retransmit; if no transport is bound, ask the
		// loop to re-dial by identity to obtain a fresh epoch (which resumes via
		// OnTransportReady).
		a.Frames = s.collectData(now)
		if s.resumeOutstanding {
			a.Frames = append(a.Frames, Frame{Sub: subResume, Session: s.id, AckOff: s.rx.rcvNxt, RcvWnd: s.rx.advertiseWnd()})
		}
		if !epochAlive {
			a.WantReDial = true
		}
		return a
	case StateClosing:
		// TIME-WAIT: the transfer is complete on both sides. Tear down when the
		// linger expires (freeing the slot + firing Done/Err) or at once if SWIM
		// says the peer is gone — there is no data left to lose either way.
		var a Action
		if !rsKnown || rs == RosterDead || rs == RosterLeft || !now.Before(s.lingerEnd) {
			s.teardown(StateClosed, ErrClosed, &a)
		}
		return a
	default:
		return Action{}
	}
}

// OnTransportReady binds a (re)connected transport epoch. On a genuinely new
// epoch it starts the resume reconciliation: rewind the sent frontier, reset the
// RTO, immediately resend the unacked window, and emit RESUME. A same-epoch call
// is a no-op (a transient same-epoch heal recovers by plain RTO retransmit).
func (s *Session) OnTransportReady(epoch uint64, now time.Time) Action {
	if s.state.Terminal() {
		return Action{}
	}
	if epoch == s.epoch && s.epoch != 0 {
		return Action{}
	}
	newEpoch := epoch != s.epoch
	s.epoch = epoch
	if s.state == StateOpening {
		// First transport bind during open: nothing to resume yet.
		return Action{}
	}
	if !newEpoch {
		return Action{}
	}
	s.state = StateResuming
	s.tx.onEpochChange(now)
	s.resumeOutstanding = true
	s.resumeCount++
	s.graceEnd = time.Time{}
	a := Action{ResumeStarted: true}
	a.Frames = append(a.Frames, Frame{Sub: subResume, Session: s.id, AckOff: s.rx.rcvNxt, RcvWnd: s.rx.advertiseWnd()})
	a.Frames = append(a.Frames, s.collectData(now)...)
	return a
}

// --- send-frame assembly ----------------------------------------------------

// collectData gathers the data-plane frames sendable now: RTO retransmits, fresh
// fills (flow-controlled), a zero-window probe, and the FIN once data is acked.
// Pure-ACK/control frames are produced elsewhere and bypass the window gate.
func (s *Session) collectData(now time.Time) []Frame {
	if s.state != StateEstablished && s.state != StateResuming && s.state != StatePaused {
		return nil
	}
	var frames []Frame
	for _, sg := range s.tx.rtoDue(now) {
		frames = append(frames, Frame{Sub: subData, Session: s.id, Offset: sg.off, Data: sg.data})
	}
	for _, sg := range s.tx.fillable(now) {
		frames = append(frames, Frame{Sub: subData, Session: s.id, Offset: sg.off, Data: sg.data})
	}
	if sg, ok := s.tx.zwpDue(now); ok {
		frames = append(frames, Frame{Sub: subData, Session: s.id, Offset: sg.off, Data: sg.data})
	}
	// FIN once all data through finOffset is acked.
	if s.pendingFin && !s.tx.finAcked && s.tx.finOffset != nil && s.tx.sndUna >= *s.tx.finOffset {
		frames = append(frames, Frame{Sub: subFin, Session: s.id, FinOff: *s.tx.finOffset})
	}
	return frames
}

func (s *Session) teardown(st State, err error, a *Action) {
	if s.state.Terminal() {
		return
	}
	s.state = st
	s.tx.out = nil
	s.rx.ooo = nil
	s.rx.oooLen = 0
	s.resumeOutstanding = false
	a.Terminated = true
	a.Err = err
}
