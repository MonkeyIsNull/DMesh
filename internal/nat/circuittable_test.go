package nat

import (
	"testing"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
)

func nid(b byte) identity.NodeID {
	var n identity.NodeID
	n[0] = b
	n[31] = b
	return n
}

func tightParams() Params {
	return Params{
		MaxCircuitsGlobal:       2,
		MaxCircuitsPerRequester: 1,
		PerCircuitBytesPerSec:   100,
		PerRequesterBytesPerSec: 1000,
		GlobalBytesPerSec:       1000,
		OpenRatePerRequester:    2,
		CircuitIdleTimeout:      10 * time.Second,
		DedupWindow:             5 * time.Second,
	}.WithDefaults()
}

func TestOpenCapsAndBinding(t *testing.T) {
	now := time.Unix(0, 0)
	ct := NewCircuitTable(tightParams())
	a, b, c := nid(1), nid(2), nid(3)

	id1, res := ct.Open(a, b, 1, 10, now)
	if res != OpenOK || id1 != 10 {
		t.Fatalf("first open: %v %d", res, id1)
	}
	// Per-requester cap (1) blocks a's second circuit.
	if _, res := ct.Open(a, c, 2, 11, now); res != OpenCapRequester {
		t.Fatalf("expected per-requester cap, got %v", res)
	}
	// Another requester can open until the global cap (2).
	if _, res := ct.Open(b, c, 1, 12, now); res != OpenOK {
		t.Fatalf("second requester open: %v", res)
	}
	// Global cap (2) now blocks everyone.
	if _, res := ct.Open(c, a, 1, 13, now); res != OpenCapGlobal {
		t.Fatalf("expected global cap, got %v", res)
	}

	// Endpoint binding: Other only resolves for a bound endpoint.
	if other, ok := ct.Other(10, a); !ok || other != b {
		t.Fatalf("Other(a) = %v %v want %v", other, ok, b)
	}
	if other, ok := ct.Other(10, b); !ok || other != a {
		t.Fatalf("Other(b) = %v %v want %v", other, ok, a)
	}
	if _, ok := ct.Other(10, c); ok {
		t.Fatal("third party resolved a circuit it is not bound to")
	}
}

func TestOpenIdempotentAndCollision(t *testing.T) {
	now := time.Unix(0, 0)
	ct := NewCircuitTable(tightParams())
	a, b := nid(1), nid(2)

	id1, res := ct.Open(a, b, 7, 100, now)
	if res != OpenOK {
		t.Fatalf("open: %v", res)
	}
	// Same (requester, nonce) within the dedup window returns the same id, even
	// with a different proposed id, and does NOT consume caps/rate.
	id2, res := ct.Open(a, b, 7, 999, now.Add(time.Second))
	if res != OpenOK || id2 != id1 {
		t.Fatalf("idempotent open returned %d/%v want %d", id2, res, id1)
	}
	if ct.Len() != 1 {
		t.Fatalf("idempotent open created a duplicate: len=%d", ct.Len())
	}
	// A proposed id already live is a collision.
	if _, res := ct.Open(b, a, 1, 100, now); res != OpenCollision {
		t.Fatalf("expected collision, got %v", res)
	}
}

func TestOpenRateLimit(t *testing.T) {
	now := time.Unix(0, 0)
	p := tightParams()
	p.MaxCircuitsPerRequester = 100
	p.MaxCircuitsGlobal = 100
	p.OpenRatePerRequester = 2 // burst 2
	ct := NewCircuitTable(p)
	a := nid(1)
	// Two opens allowed from the initial burst.
	if _, r := ct.Open(a, nid(2), 1, 1, now); r != OpenOK {
		t.Fatalf("open1 %v", r)
	}
	if _, r := ct.Open(a, nid(3), 2, 2, now); r != OpenOK {
		t.Fatalf("open2 %v", r)
	}
	// Third within the same instant is rate-limited.
	if _, r := ct.Open(a, nid(4), 3, 3, now); r != OpenRateLimited {
		t.Fatalf("expected rate-limited, got %v", r)
	}
	// After a second, one token refilled.
	if _, r := ct.Open(a, nid(5), 4, 4, now.Add(time.Second)); r != OpenOK {
		t.Fatalf("expected refill, got %v", r)
	}
}

func TestChargeBudgets(t *testing.T) {
	now := time.Unix(0, 0)
	p := tightParams()
	p.PerCircuitBytesPerSec = 100 // burst 100 bytes
	p.GlobalBytesPerSec = 150
	ct := NewCircuitTable(p)
	a, b := nid(1), nid(2)
	ct.Open(a, b, 1, 1, now)

	// Global ceiling (150) allows one 100-byte and then only 50 more.
	if !ct.ChargeGlobal(100, now) {
		t.Fatal("global charge 1 should pass")
	}
	if !ct.Charge(1, 100, now) {
		t.Fatal("per-circuit charge 1 should pass")
	}
	// Per-circuit bucket (100) is now empty: next data frame shed.
	if ct.Charge(1, 100, now) {
		t.Fatal("per-circuit over budget should be shed")
	}
	// Global shed-first: a second 100-byte exceeds the 150 ceiling.
	if ct.ChargeGlobal(100, now) {
		t.Fatal("global over ceiling should be shed")
	}
	// Refill after a second.
	if !ct.Charge(1, 100, now.Add(time.Second)) {
		t.Fatal("per-circuit should refill")
	}
}

func TestReapIdleSortedAndClose(t *testing.T) {
	now := time.Unix(0, 0)
	p := tightParams()
	p.MaxCircuitsGlobal = 100
	p.MaxCircuitsPerRequester = 100
	p.CircuitIdleTimeout = 10 * time.Second
	ct := NewCircuitTable(p)
	ct.Open(nid(1), nid(9), 1, 30, now)
	ct.Open(nid(2), nid(9), 1, 10, now)
	ct.Open(nid(3), nid(9), 1, 20, now)

	// Touch id 20 so only 10 and 30 go idle.
	ct.Touch(20, now.Add(5*time.Second))
	ids := ct.ReapIdle(now.Add(11 * time.Second))
	if len(ids) != 2 || ids[0] != 10 || ids[1] != 30 {
		t.Fatalf("reap ids not sorted/selected: %v", ids)
	}
	if ct.Exists(10) || ct.Exists(30) || !ct.Exists(20) {
		t.Fatal("reap did not close the right circuits")
	}
	// Close frees the per-requester slot.
	ct.Close(20)
	if ct.perReq[nid(3)] != 0 {
		t.Fatalf("per-requester slot not freed: %d", ct.perReq[nid(3)])
	}
}

func TestTokenBucketUnlimited(t *testing.T) {
	b := &tokenBucket{rate: 0}
	if !b.allow(1e9, time.Unix(0, 0)) {
		t.Fatal("zero-rate bucket should be unlimited")
	}
}

// TestHandshakeGraceBounded proves the handshake exemption is a bounded, one-time
// per-circuit budget: a few small handshake frames pass exempt, but once the
// grace is spent, further handshake-typed frames are NOT exempt and must be
// charged against the byte buckets exactly like data (so a sustained flood of
// handshake-typed frames can no longer bypass the per-circuit rate limit).
func TestHandshakeGraceBounded(t *testing.T) {
	now := time.Unix(0, 0)
	p := tightParams()
	p.HandshakeGraceBytes = 250 // room for exactly two 100-byte handshake frames
	p.PerCircuitBytesPerSec = 100
	p.PerRequesterBytesPerSec = 1000
	p.GlobalBytesPerSec = 1000
	ct := NewCircuitTable(p)
	a, b := nid(1), nid(2)
	ct.Open(a, b, 1, 1, now)

	// Two 100-byte handshake frames fit the 250-byte grace: exempt, uncharged.
	if !ct.ConsumeHandshakeGrace(1, 100) || !ct.ConsumeHandshakeGrace(1, 100) {
		t.Fatal("the inner handshake frames should be grace-exempt")
	}
	// Grace is now 50: a third 100-byte handshake frame does not fit, so it is NOT
	// exempt and consumes no grace - the caller must charge it like data.
	if ct.ConsumeHandshakeGrace(1, 100) {
		t.Fatal("a handshake frame past the grace budget must not be exempt")
	}
	// Charged like data: the per-circuit bucket (burst 100) admits one 100-byte
	// frame then sheds the rest of the flood at a frozen clock.
	if !ct.ChargeGlobal(100, now) || !ct.Charge(1, 100, now) {
		t.Fatal("first charged handshake-overflow frame should pass on a full bucket")
	}
	if ct.Charge(1, 100, now) {
		t.Fatal("per-circuit bucket exhausted: a sustained handshake-typed flood must be shed")
	}
	// The grace is one-time and never refills: the 50 bytes left cover a 50-byte
	// frame once, after which nothing is exempt.
	if !ct.ConsumeHandshakeGrace(1, 50) {
		t.Fatal("the remaining grace should cover one last small frame")
	}
	if ct.ConsumeHandshakeGrace(1, 1) {
		t.Fatal("grace must not refill once spent")
	}
}
