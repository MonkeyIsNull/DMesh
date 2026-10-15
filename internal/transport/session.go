package transport

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/flynn/noise"
)

// Session owns the two CipherStates produced by a completed handshake and
// enforces the two hard AEAD safety rules:
//
//  1. SEND: ChaCha20-Poly1305 nonce reuse is a catastrophic break, so there is
//     exactly ONE serialized writer with ONE atomic monotonic nonce counter as
//     the sole nonce source. flynn/noise CipherState.n is unlocked mutable
//     state, so no CipherState is ever touched by two goroutines.
//
//  2. RECEIVE: an RFC-6479 two-phase sliding replay window scoped to this
//     session's cipher epoch. The window bit is set ONLY after the AEAD tag
//     verifies, so a forged tag at a future nonce cannot poison the window and
//     evict legitimate in-flight frames.
type Session struct {
	peerIndex  uint32 // receiverIndex to stamp on outbound data frames
	localIndex uint32

	sendMu   sync.Mutex
	send     *noise.CipherState
	sendN    atomic.Uint64
	sendDead atomic.Bool

	recvMu sync.Mutex
	recv   *noise.CipherState
	window replayWindow
}

// ErrSessionClosed is returned once the session has been torn down.
var ErrSessionClosed = errors.New("transport: session closed")

// ErrReplay is returned by Open for a replayed or stale nonce.
var ErrReplay = errors.New("transport: replayed or stale nonce")

// ErrPayloadTooLarge is returned by Seal for a plaintext that would not fit a
// single datagram once the AEAD tag is added.
var ErrPayloadTooLarge = errors.New("transport: plaintext exceeds max payload")

// NewSession builds a session from a handshake result. If the result carries a
// first authenticated frame already consumed during the handshake (the
// responder's HELLO, which acks msg3 for the initiator), its nonce is committed
// to the replay window here so that frame falls under the same per-epoch replay
// protection as every subsequent frame - a captured copy cannot be replayed in.
func NewSession(r *HandshakeResult) *Session {
	s := &Session{
		peerIndex:  r.PeerIndex,
		localIndex: r.LocalIndex,
		send:       r.Send,
		recv:       r.Recv,
	}
	if r.HasFirst {
		s.window.commit(r.FirstNonce)
	}
	return s
}

// LocalIndex returns the local connection index.
func (s *Session) LocalIndex() uint32 { return s.localIndex }

// Seal encrypts plaintext into a ready-to-send data frame. It takes the single
// nonce atomically, so concurrent callers never reuse a nonce. The nonce is
// carried explicitly in the frame header.
func (s *Session) Seal(plaintext []byte) ([]byte, error) {
	if s.sendDead.Load() {
		return nil, ErrSessionClosed
	}
	// Enforce the single-datagram size invariant symmetrically with the decode
	// side: the ciphertext (plaintext + AEAD tag) must fit MaxPayload, which the
	// peer's decodeData caps and the uint16 length header requires. Reject on
	// send rather than emit a frame the peer would drop (or, for a >64KiB
	// plaintext, one whose uint16 length would wrap).
	if len(plaintext) > MaxPlaintext {
		return nil, ErrPayloadTooLarge
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	n := s.sendN.Load()
	if n >= noise.MaxNonce {
		s.sendDead.Store(true)
		return nil, noise.ErrMaxNonce
	}
	s.send.SetNonce(n)
	ct, err := s.send.Encrypt(nil, nil, plaintext)
	if err != nil {
		return nil, err
	}
	s.sendN.Store(n + 1)
	return encodeData(flagNone, s.peerIndex, n, ct), nil
}

// Open verifies and decrypts a received data frame. It applies the RFC-6479
// two-phase window: step 1 rejects a nonce below the window or whose bit is
// already set; step 2 decrypts; step 3 records the nonce ONLY on successful
// authentication.
func (s *Session) Open(df dataFrame) ([]byte, error) {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()

	// Phase 1: cheap pre-check against the window (no state mutation).
	if !s.window.check(df.nonce) {
		return nil, ErrReplay
	}
	// Phase 2: authenticate+decrypt under the wire nonce.
	s.recv.SetNonce(df.nonce)
	pt, err := s.recv.Decrypt(nil, nil, df.ciphertext)
	if err != nil {
		return nil, err
	}
	// Phase 3: commit to the window only after the tag verified.
	s.window.commit(df.nonce)
	return pt, nil
}

// OpenFrame decodes a data datagram and opens it. It returns ErrReplay for a
// stale/replayed nonce, or a decryption error for a forged/undecryptable frame.
func (s *Session) OpenFrame(b []byte) ([]byte, error) {
	df, err := decodeData(b)
	if err != nil {
		return nil, err
	}
	return s.Open(df)
}

// Close marks the send side dead so no further frames are produced.
func (s *Session) Close() {
	s.sendDead.Store(true)
}

// replayWindow is an RFC-6479 bitmap sliding window over 64-bit nonces.
type replayWindow struct {
	seen    bool   // whether any nonce has been accepted yet
	highest uint64 // highest accepted nonce
	bits    uint64 // bitmap; bit i set => (highest - i) accepted
}

const windowSize = 64

// check reports whether nonce n could be accepted (phase 1). It does not
// mutate state.
func (w *replayWindow) check(n uint64) bool {
	if !w.seen {
		return true
	}
	if n > w.highest {
		return true
	}
	diff := w.highest - n
	if diff >= windowSize {
		return false // too old
	}
	return w.bits&(1<<diff) == 0
}

// commit records nonce n as accepted (phase 3), after authentication.
func (w *replayWindow) commit(n uint64) {
	if !w.seen {
		w.seen = true
		w.highest = n
		w.bits = 1
		return
	}
	if n > w.highest {
		shift := n - w.highest
		if shift >= windowSize {
			w.bits = 1
		} else {
			w.bits = (w.bits << shift) | 1
		}
		w.highest = n
		return
	}
	diff := w.highest - n
	if diff < windowSize {
		w.bits |= 1 << diff
	}
}
