package transport

import (
	"sync"
	"testing"

	"github.com/flynn/noise"
)

// rawConnect completes an in-process XXpsk0 handshake and returns the two
// handshake results (initiator, responder) with cipher states set.
func rawConnect(t *testing.T) (*HandshakeResult, *HandshakeResult) {
	t.Helper()
	idI, idR := genID(t), genID(t)
	psk := testPSK(t)
	hsI := newHS(t, true, idI, psk)
	hsR := newHS(t, false, idR, psk)

	m1, _, _, err := hsI.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := hsR.ReadMessage(nil, m1); err != nil {
		t.Fatal(err)
	}
	m2, _, _, err := hsR.WriteMessage(nil, bindingPayload(idR))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := hsI.ReadMessage(nil, m2); err != nil {
		t.Fatal(err)
	}
	m3, iSend, iRecv, err := hsI.WriteMessage(nil, bindingPayload(idI))
	if err != nil {
		t.Fatal(err)
	}
	_, rRecv, rSend, err := hsR.ReadMessage(nil, m3)
	if err != nil {
		t.Fatal(err)
	}
	return &HandshakeResult{Send: iSend, Recv: iRecv, PeerIndex: 0x2222, LocalIndex: 0x1111},
		&HandshakeResult{Send: rSend, Recv: rRecv, PeerIndex: 0x1111, LocalIndex: 0x2222}
}

func TestSessionInOrderAndReplay(t *testing.T) {
	iRes, rRes := rawConnect(t)
	iSess, rSess := NewSession(iRes), NewSession(rRes)

	f0, _ := iSess.Seal([]byte("zero"))
	f1, _ := iSess.Seal([]byte("one"))
	f2, _ := iSess.Seal([]byte("two"))

	if pt, err := rSess.OpenFrame(f0); err != nil || string(pt) != "zero" {
		t.Fatalf("f0: %q %v", pt, err)
	}
	// Out-of-order within the window is accepted.
	if pt, err := rSess.OpenFrame(f2); err != nil || string(pt) != "two" {
		t.Fatalf("f2: %q %v", pt, err)
	}
	if pt, err := rSess.OpenFrame(f1); err != nil || string(pt) != "one" {
		t.Fatalf("f1: %q %v", pt, err)
	}
	// Replay of an already-seen frame is rejected.
	if _, err := rSess.OpenFrame(f1); err != ErrReplay {
		t.Fatalf("replay err = %v, want ErrReplay", err)
	}
	if _, err := rSess.OpenFrame(f0); err != ErrReplay {
		t.Fatalf("replay err = %v, want ErrReplay", err)
	}
}

func TestReplayWindow(t *testing.T) {
	var w replayWindow

	if !w.check(5) {
		t.Fatal("first nonce rejected")
	}
	w.commit(5)
	// Duplicate of highest rejected.
	if w.check(5) {
		t.Fatal("duplicate of highest accepted")
	}
	// In-window older nonce accepted once, then rejected.
	if !w.check(3) {
		t.Fatal("in-window nonce rejected")
	}
	w.commit(3)
	if w.check(3) {
		t.Fatal("replayed in-window nonce accepted")
	}
	// Advance far ahead; old nonce now below the window.
	w.commit(200)
	if w.check(5) {
		t.Fatal("stale nonce below window accepted")
	}
	// Edge: exactly windowSize-1 below highest is still in window.
	if !w.check(200 - (windowSize - 1)) {
		t.Fatal("window-edge nonce rejected")
	}
	// windowSize below highest is out.
	if w.check(200 - windowSize) {
		t.Fatal("just-past-edge nonce accepted")
	}
}

func TestReplayWindowForgedTagDoesNotPoison(t *testing.T) {
	// RFC-6479 two-phase: a forged frame at a far-future nonce that FAILS the
	// AEAD must not advance the window. We model phase 3 (commit) running only
	// on auth success: a legitimate in-flight frame after the forged attempt is
	// still accepted.
	iRes, rRes := rawConnect(t)
	iSess, rSess := NewSession(iRes), NewSession(rRes)

	// Seal three legit frames (nonces 0,1,2).
	f0, _ := iSess.Seal([]byte("a"))
	f1, _ := iSess.Seal([]byte("b"))
	f2, _ := iSess.Seal([]byte("c"))

	// A forged frame at nonce 1000 with a bad tag: Open must fail and NOT
	// advance the window (commit is never reached).
	forged := encodeData(flagNone, rRes.LocalIndex, 1000, []byte("garbage-ciphertext"))
	if _, err := rSess.OpenFrame(forged); err == nil {
		t.Fatal("forged frame authenticated")
	}
	// The legit frames still open in order - the window was not poisoned.
	for i, f := range [][]byte{f0, f1, f2} {
		if _, err := rSess.OpenFrame(f); err != nil {
			t.Fatalf("legit frame %d rejected after forged attempt: %v", i, err)
		}
	}
}

func TestSealRejectsOversizePayload(t *testing.T) {
	iRes, rRes := rawConnect(t)
	iSess, rSess := NewSession(iRes), NewSession(rRes)

	// The largest accepted plaintext seals and opens round-trip.
	big := make([]byte, MaxPlaintext)
	f, err := iSess.Seal(big)
	if err != nil {
		t.Fatalf("max-size plaintext rejected: %v", err)
	}
	if _, err := rSess.OpenFrame(f); err != nil {
		t.Fatalf("peer rejected a max-size frame: %v", err)
	}
	// One byte over the cap is rejected on the send side, symmetric with the
	// receiver's decodeData cap.
	if _, err := iSess.Seal(make([]byte, MaxPlaintext+1)); err != ErrPayloadTooLarge {
		t.Fatalf("err = %v, want ErrPayloadTooLarge", err)
	}
}

// TestFirstFrameReplayWindowSeeded proves NewSession seeds the replay window
// with the handshake's first-frame nonce, so a captured copy of that frame
// cannot be replayed into the session (the msg3-loss-recovery gap).
func TestFirstFrameReplayWindowSeeded(t *testing.T) {
	iRes, rRes := rawConnect(t)
	// Model the initiator's view: the responder's first authenticated frame was
	// consumed during the handshake at nonce 0. The responder (sender) would
	// seal it from its own session, advancing its nonce past 0.
	rSess := NewSession(rRes)
	firstFrame, err := rSess.Seal([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	df, err := decodeData(firstFrame)
	if err != nil {
		t.Fatal(err)
	}
	iRes.FirstPayload = []byte("hello")
	iRes.FirstNonce = df.nonce
	iRes.HasFirst = true

	iSess := NewSession(iRes)
	// Replaying the exact first frame into the initiator's session must be
	// rejected as stale - its nonce was committed at construction.
	if _, err := iSess.OpenFrame(firstFrame); err != ErrReplay {
		t.Fatalf("first-frame replay err = %v, want ErrReplay", err)
	}
	// A genuine subsequent frame (next nonce) still opens.
	next, err := rSess.Seal([]byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := iSess.OpenFrame(next); err != nil || string(pt) != "second" {
		t.Fatalf("subsequent frame: %q %v", pt, err)
	}
}

func TestSessionMaxNonce(t *testing.T) {
	iRes, _ := rawConnect(t)
	iSess := NewSession(iRes)
	iSess.sendN.Store(noise.MaxNonce)
	if _, err := iSess.Seal([]byte("x")); err != noise.ErrMaxNonce {
		t.Fatalf("err = %v, want ErrMaxNonce", err)
	}
}

func TestConcurrentSendNoNonceReuse(t *testing.T) {
	iRes, rRes := rawConnect(t)
	iSess, rSess := NewSession(iRes), NewSession(rRes)

	const n = 50
	frames := make([][]byte, n)
	var wg sync.WaitGroup
	// Concurrent app-sends AND a keep-alive-like stream all funnel through the
	// single serialized send path; -race must see no data race and no reuse.
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			f, err := iSess.Seal([]byte{byte(i)})
			if err != nil {
				t.Errorf("seal: %v", err)
				return
			}
			frames[i] = f
		}(i)
	}
	wg.Wait()

	// Every frame must have a distinct nonce and decrypt successfully.
	seen := make(map[uint64]bool)
	ok := 0
	for _, f := range frames {
		df, err := decodeData(f)
		if err != nil {
			t.Fatal(err)
		}
		if seen[df.nonce] {
			t.Fatalf("nonce %d reused - catastrophic", df.nonce)
		}
		seen[df.nonce] = true
	}
	// Decrypt in nonce order so all land within the replay window.
	for nonce := uint64(0); nonce < n; nonce++ {
		for _, f := range frames {
			df, _ := decodeData(f)
			if df.nonce == nonce {
				if _, err := rSess.Open(df); err != nil {
					t.Fatalf("open nonce %d: %v", nonce, err)
				}
				ok++
			}
		}
	}
	if ok != n {
		t.Fatalf("opened %d frames, want %d", ok, n)
	}
}
