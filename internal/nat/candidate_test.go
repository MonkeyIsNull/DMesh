package nat

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
)

func mustID(t *testing.T, seed int64) *identity.Identity {
	t.Helper()
	id, err := identity.GenerateFrom("", rand.New(rand.NewSource(seed)))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func ap(s string) netip.AddrPort {
	return netip.MustParseAddrPort(s)
}

func TestSignVerifyRoundTrip(t *testing.T) {
	id := mustID(t, 1)
	cands := []Candidate{
		{Addr: ap("192.168.1.5:9000"), Type: CandHost},
		{Addr: ap("203.0.113.9:4500"), Type: CandReflexive},
	}
	cs := SignSelf(id, 7, CapRelay|CapNat, cands)
	if cs.Gen != 7 {
		t.Fatalf("gen = %d", cs.Gen)
	}
	if !Verify(id.NodeID(), cs) {
		t.Fatal("own set did not verify")
	}
	// A different subject must not verify.
	other := mustID(t, 2)
	if Verify(other.NodeID(), cs) {
		t.Fatal("set verified against the wrong subject")
	}
}

func TestVerifyRejectsTamper(t *testing.T) {
	id := mustID(t, 3)
	cs := SignSelf(id, 1, CapNat, []Candidate{{Addr: ap("10.0.0.1:1"), Type: CandHost}})
	// Tamper a candidate: signature must fail (it is over the canonical set).
	bad := cs
	bad.Cands = []Candidate{{Addr: ap("10.0.0.2:1"), Type: CandHost}}
	if Verify(id.NodeID(), bad) {
		t.Fatal("tampered candidate set verified")
	}
	// Tamper the generation.
	badGen := cs
	badGen.Gen = 2
	if Verify(id.NodeID(), badGen) {
		t.Fatal("tampered gen verified")
	}
	// Tamper caps.
	badCaps := cs
	badCaps.Caps = CapRelay
	if Verify(id.NodeID(), badCaps) {
		t.Fatal("tampered caps verified")
	}
	// Wrong-length signature.
	badSig := cs
	badSig.Sig = cs.Sig[:len(cs.Sig)-1]
	if Verify(id.NodeID(), badSig) {
		t.Fatal("truncated signature verified")
	}
}

func TestVerifyOrderIndependent(t *testing.T) {
	id := mustID(t, 4)
	cands := []Candidate{
		{Addr: ap("203.0.113.9:4500"), Type: CandReflexive},
		{Addr: ap("192.168.1.5:9000"), Type: CandHost},
	}
	cs := SignSelf(id, 1, 0, cands)
	// Reorder the carried candidates; Verify re-sorts, so it must still pass.
	reordered := cs
	reordered.Cands = []Candidate{cs.Cands[len(cs.Cands)-1], cs.Cands[0]}
	if len(reordered.Cands) == len(cs.Cands) {
		if !Verify(id.NodeID(), reordered) {
			t.Fatal("reordered candidate set failed to verify")
		}
	}
}

func TestDedupSortEvictionStable(t *testing.T) {
	in := []Candidate{
		{Addr: ap("10.0.0.3:1"), Type: CandHost},         // private -> rank 2
		{Addr: ap("203.0.113.1:1"), Type: CandHost},      // public  -> rank 0
		{Addr: ap("203.0.113.9:1"), Type: CandReflexive}, // reflexive -> rank 1
		{Addr: ap("10.0.0.3:1"), Type: CandHost},         // dup of first
	}
	s := DedupSort(in)
	if len(s) != 3 {
		t.Fatalf("dedup failed: got %d want 3", len(s))
	}
	if s[0].Type != CandHost || s[0].Addr != ap("203.0.113.1:1") {
		t.Fatalf("host-public not first: %+v", s[0])
	}
	if s[1].Type != CandReflexive {
		t.Fatalf("reflexive not second: %+v", s[1])
	}
	if s[2].Type != CandHost || s[2].Addr != ap("10.0.0.3:1") {
		t.Fatalf("host-private not last: %+v", s[2])
	}
	// Idempotent / convergent: sorting twice yields the same order.
	s2 := DedupSort(s)
	for i := range s {
		if s[i] != s2[i] {
			t.Fatal("DedupSort not idempotent")
		}
	}
	// Bounded set keeps the highest-priority N and never oscillates.
	b1 := BoundSet(in, 2)
	b2 := BoundSet(append([]Candidate{in[0]}, in...), 2)
	if len(b1) != 2 || len(b2) != 2 || b1[0] != b2[0] || b1[1] != b2[1] {
		t.Fatalf("bounded set not convergent: %+v vs %+v", b1, b2)
	}
}

func TestPrimary(t *testing.T) {
	if got := Primary([]Candidate{
		{Addr: ap("10.0.0.3:1"), Type: CandHost},
		{Addr: ap("203.0.113.1:1"), Type: CandHost},
	}); got != ap("203.0.113.1:1") {
		t.Fatalf("primary = %v want public host", got)
	}
	// Only a relay candidate -> no direct dial hint.
	if got := Primary([]Candidate{{Addr: ap("203.0.113.1:1"), Type: CandRelay}}); got.IsValid() {
		t.Fatalf("relay-only primary should be invalid, got %v", got)
	}
	if got := Primary(nil); got.IsValid() {
		t.Fatal("empty primary should be invalid")
	}
}

func TestEqual(t *testing.T) {
	a := CandSet{Caps: CapNat, Cands: []Candidate{{Addr: ap("1.2.3.4:5"), Type: CandHost}}}
	b := CandSet{Caps: CapNat, Gen: 99, Cands: []Candidate{{Addr: ap("1.2.3.4:5"), Type: CandHost}}}
	if !Equal(a, b) {
		t.Fatal("sets differing only in gen should be Equal")
	}
	c := CandSet{Caps: CapRelay, Cands: a.Cands}
	if Equal(a, c) {
		t.Fatal("sets with different caps should not be Equal")
	}
}
