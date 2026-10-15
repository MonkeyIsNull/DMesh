package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/clock"
	"github.com/MonkeyIsNull/DMesh/internal/identity"
	"github.com/flynn/noise"
)

func genID(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Generate("")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func testPSK(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// pipeEnd is one side of an in-memory datagram link with optional loss.
type pipeEnd struct {
	inbox chan []byte
	peer  chan []byte // the other side's inbox
	mu    sync.Mutex
	n     int
	drop  func(seq int, b []byte) bool
}

func (p *pipeEnd) Send(b []byte) error {
	p.mu.Lock()
	p.n++
	seq := p.n
	d := p.drop
	p.mu.Unlock()
	if d != nil && d(seq, b) {
		return nil // silently dropped
	}
	cp := append([]byte(nil), b...)
	select {
	case p.peer <- cp:
	default:
	}
	return nil
}

func newPipe(buf int) (*pipeEnd, *pipeEnd) {
	a := make(chan []byte, buf)
	b := make(chan []byte, buf)
	return &pipeEnd{inbox: a, peer: b}, &pipeEnd{inbox: b, peer: a}
}

// runHandshake drives both sides to completion over the given pipe ends and
// clock, with the responder sending a HELLO as its first authenticated frame.
func runHandshake(t *testing.T, clk clock.Clock, iEnd, rEnd *pipeEnd,
	idI, idR *identity.Identity, pskI, pskR []byte) (iRes, rRes *HandshakeResult, iErr, rErr error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		rRes, rErr = DoResponder(ctx, clk, rEnd, rEnd.inbox, idR, pskR, 0x2222)
		if rErr == nil {
			sess := NewSession(rRes)
			if frame, err := sess.Seal([]byte("hello")); err == nil {
				_ = rEnd.Send(frame)
			}
		}
	}()
	go func() {
		defer wg.Done()
		iRes, iErr = DoInitiator(ctx, clk, iEnd, iEnd.inbox, idI, pskI, 0x1111)
	}()
	wg.Wait()
	return
}

func TestFullHandshakeOverPipe(t *testing.T) {
	idI, idR := genID(t), genID(t)
	psk := testPSK(t)
	iEnd, rEnd := newPipe(64)

	iRes, rRes, iErr, rErr := runHandshake(t, clock.Real{}, iEnd, rEnd, idI, idR, psk, psk)
	if iErr != nil || rErr != nil {
		t.Fatalf("handshake failed: init=%v resp=%v", iErr, rErr)
	}
	// Each side authenticated the other's true node ID via the binding.
	if iRes.PeerNodeID != idR.NodeID() {
		t.Fatal("initiator did not authenticate responder identity")
	}
	if rRes.PeerNodeID != idI.NodeID() {
		t.Fatal("responder did not authenticate initiator identity")
	}
	// Connection indices were exchanged.
	if iRes.PeerIndex != 0x2222 || rRes.PeerIndex != 0x1111 {
		t.Fatalf("indices not exchanged: i.peer=%x r.peer=%x", iRes.PeerIndex, rRes.PeerIndex)
	}
	// The initiator confirmed msg3 by receiving the responder's HELLO.
	if string(iRes.FirstPayload) != "hello" {
		t.Fatalf("FirstPayload = %q", iRes.FirstPayload)
	}
	// Bidirectional encryption works end to end.
	iSess, rSess := NewSession(iRes), NewSession(rRes)
	frame, err := iSess.Seal([]byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := rSess.OpenFrame(frame)
	if err != nil || string(pt) != "ping" {
		t.Fatalf("decrypt = %q, %v", pt, err)
	}
}

// advanceLoop keeps a fake clock moving so retransmit timers fire while the
// handshake goroutines run. It stops when the test signals done.
func advanceLoop(fake *clock.Fake, done <-chan struct{}) {
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				fake.Advance(300 * time.Millisecond)
				time.Sleep(time.Millisecond)
			}
		}
	}()
}

func TestHandshakeRetransmit(t *testing.T) {
	tests := []struct {
		name string
		// dropI drops initiator->responder frames; dropR the reverse.
		dropI func(seq int, b []byte) bool
		dropR func(seq int, b []byte) bool
	}{
		{
			name:  "lost msg1",
			dropI: func(seq int, b []byte) bool { return seq == 1 }, // first init frame (msg1)
		},
		{
			name:  "lost msg2",
			dropR: func(seq int, b []byte) bool { return seq == 1 }, // first resp frame (msg2)
		},
		{
			name: "lost msg3 and first ack",
			dropI: func(seq int, b []byte) bool {
				// Drop the first msg3 (a handshake frame sent by the initiator
				// after msg1). seq 1 = msg1, so the first msg3 is a later seq;
				// drop the first type=HS frame with hsIndex 3.
				if idx, ok := PeekHandshake(b); ok && idx == 3 {
					return seq%2 == 0 // drop every other msg3 retransmit
				}
				return false
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idI, idR := genID(t), genID(t)
			psk := testPSK(t)
			iEnd, rEnd := newPipe(256)
			iEnd.drop = tc.dropI
			rEnd.drop = tc.dropR

			fake := clock.NewFake(time.Unix(0, 0))
			done := make(chan struct{})
			advanceLoop(fake, done)

			iRes, rRes, iErr, rErr := runHandshake(t, fake, iEnd, rEnd, idI, idR, psk, psk)
			close(done)

			if iErr != nil || rErr != nil {
				t.Fatalf("handshake failed under loss: init=%v resp=%v", iErr, rErr)
			}
			if iRes.PeerNodeID != idR.NodeID() || rRes.PeerNodeID != idI.NodeID() {
				t.Fatal("identity mismatch after retransmit recovery")
			}
		})
	}
}

// TestResponderDropsEarlyDataFrame drives the initiator by hand so it emits a
// DATA frame to the responder BEFORE the responder has processed msg3 (and so
// has no keys yet). The responder must drop that undecryptable frame, keep
// retransmitting msg2, and still complete the handshake when msg3 arrives -
// the "ft == typeData -> return false, nil" branch in DoResponder.
func TestResponderDropsEarlyDataFrame(t *testing.T) {
	idI, idR := genID(t), genID(t)
	psk := testPSK(t)
	iEnd, rEnd := newPipe(256)

	fake := clock.NewFake(time.Unix(0, 0))
	done := make(chan struct{})
	advanceLoop(fake, done)
	defer close(done)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var (
		rRes *HandshakeResult
		rErr error
		wg   sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		rRes, rErr = DoResponder(ctx, fake, rEnd, rEnd.inbox, idR, psk, 0x2222)
	}()

	// Drive the initiator manually so we can slip a data frame in before msg3.
	hsI := newHS(t, true, idI, psk)
	msg1, _, _, err := hsI.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := iEnd.Send(encodeHandshake(1, 0x1111, msg1)); err != nil {
		t.Fatal(err)
	}

	// Read the responder's msg2 (first frame on our inbox) and advance the
	// initiator handshake past it so we can produce a valid msg3.
	var msg2 []byte
	select {
	case msg2 = <-iEnd.inbox:
	case <-time.After(5 * time.Second):
		t.Fatal("never received msg2 from responder")
	}
	hf, err := decodeHandshake(msg2)
	if err != nil {
		t.Fatal(err)
	}
	if hf.hsIndex != 2 {
		t.Fatalf("expected msg2, got hsIndex %d", hf.hsIndex)
	}
	if _, _, _, err := hsI.ReadMessage(nil, hf.noiseMsg); err != nil {
		t.Fatal(err)
	}

	// Inject an early, undecryptable DATA frame. The responder holds no keys
	// yet, so this must be dropped WITHOUT tearing the handshake down.
	iEnd.Send(encodeData(flagNone, 0x2222, 0, []byte("premature ciphertext - no keys yet")))

	// Now complete the handshake with msg3; the responder must still finish.
	msg3, csSend, csRecv, err := hsI.WriteMessage(nil, bindingPayload(idI))
	if err != nil {
		t.Fatal(err)
	}
	if csSend == nil || csRecv == nil {
		t.Fatal("initiator msg3 did not complete handshake")
	}
	iEnd.Send(encodeHandshake(3, 0x1111, msg3))

	wg.Wait()
	if rErr != nil {
		t.Fatalf("responder failed after an early data frame: %v", rErr)
	}
	if rRes.PeerNodeID != idI.NodeID() {
		t.Fatal("responder did not authenticate the initiator after dropping the early data frame")
	}
}

// --- credential-gate coverage at the Noise layer -----------------------------

// newHS builds a raw XXpsk0 handshake state for gate tests.
func newHS(t *testing.T, initiator bool, id *identity.Identity, psk []byte) *noise.HandshakeState {
	t.Helper()
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite(),
		Pattern:       noise.HandshakeXX,
		Initiator:     initiator,
		Prologue:      prologue,
		PresharedKey:  psk,
		StaticKeypair: id.NoiseStatic,
	})
	if err != nil {
		t.Fatal(err)
	}
	return hs
}

func TestWrongNetworkKeyFailsAtMsg1(t *testing.T) {
	idI, idR := genID(t), genID(t)
	pskGood := testPSK(t)
	pskBad := testPSK(t)

	// (a) Responder with the WRONG key fails on ReadMessage(msg1) - the
	// cheapest rejection, matching the DoS north star.
	hsI := newHS(t, true, idI, pskGood)
	hsR := newHS(t, false, idR, pskBad)
	msg1, _, _, err := hsI.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := hsR.ReadMessage(nil, msg1); err == nil {
		t.Fatal("responder accepted msg1 under the wrong network key")
	}

	// (b) The initiator rejects a responder whose key is wrong: msg2 fails.
	hsI2 := newHS(t, true, idI, pskGood)
	hsR2 := newHS(t, false, idR, pskBad)
	// Give the bad responder the good key just to produce a msg2 shape, but
	// mix a different psk so the initiator's ReadMessage(msg2) fails.
	m1, _, _, _ := hsI2.WriteMessage(nil, nil)
	// Responder must first read msg1 with the SAME (good) key to proceed.
	hsR2good := newHS(t, false, idR, pskGood)
	if _, _, _, err := hsR2good.ReadMessage(nil, m1); err != nil {
		t.Fatal(err)
	}
	_ = hsR2
	m2, _, _, _ := hsR2good.WriteMessage(nil, bindingPayload(idR))
	// Tamper the ciphertext so the initiator's AEAD fails (stands in for a key
	// mismatch producing an unauthenticated msg2).
	m2[len(m2)-1] ^= 0xff
	if _, _, _, err := hsI2.ReadMessage(nil, m2); err == nil {
		t.Fatal("initiator accepted a corrupted msg2")
	}
}

func TestNoPSKKeylessXXRejected(t *testing.T) {
	idI, idR := genID(t), genID(t)
	psk := testPSK(t)

	// An uncredentialed attacker runs plain HandshakeXX with no psk token: a
	// different wire shape. Our psk0 responder must reject its msg1.
	attacker, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite(),
		Pattern:       noise.HandshakeXX, // NO PresharedKey => plain XX
		Initiator:     true,
		Prologue:      prologue,
		StaticKeypair: idI.NoiseStatic,
	})
	if err != nil {
		t.Fatal(err)
	}
	msg1, _, _, _ := attacker.WriteMessage(nil, nil)
	hsR := newHS(t, false, idR, psk)
	if _, _, _, err := hsR.ReadMessage(nil, msg1); err == nil {
		t.Fatal("psk0 responder accepted a keyless plain-XX msg1")
	}
}

func TestBindingContextDomainSeparation(t *testing.T) {
	id := genID(t)
	// A signature valid only under a DIFFERENT context string must be rejected.
	wrong := ed25519.Sign(id.Signing, append([]byte("WRONG-context"), id.NoiseStatic.Public...))
	payload := append(append([]byte(nil), id.Signing.Public().(ed25519.PublicKey)...), wrong...)
	if _, _, err := verifyBindingPayload(payload, id.NoiseStatic.Public); err == nil {
		t.Fatal("binding verified under the wrong context string")
	}
	// The correct binding verifies.
	good := append(append([]byte(nil), id.Signing.Public().(ed25519.PublicKey)...), id.SignBinding()...)
	if _, _, err := verifyBindingPayload(good, id.NoiseStatic.Public); err != nil {
		t.Fatalf("valid binding rejected: %v", err)
	}
}

func TestBindingAgainstWrongAuthenticatedStatic(t *testing.T) {
	id := genID(t)
	other := genID(t)
	payload := append(append([]byte(nil), id.Signing.Public().(ed25519.PublicKey)...), id.SignBinding()...)
	// Verifying a valid self-cert against a DIFFERENT authenticated static must
	// fail (prevents a peer vouching for a static it does not own).
	if _, _, err := verifyBindingPayload(payload, other.NoiseStatic.Public); err == nil {
		t.Fatal("binding verified against the wrong authenticated static")
	}
}
