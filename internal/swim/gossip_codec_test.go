package swim

import (
	"bytes"
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
	"github.com/MonkeyIsNull/DMesh/internal/transport"
)

func TestGossipBufferRetiresAfterBudget(t *testing.T) {
	b := NewBuffer(0)
	u := Update{NodeID: idN(1), Incarnation: 1, State: StateAlive}
	b.Add(u, 3)
	seen := 0
	for i := 0; i < 5; i++ {
		got := b.Pick(10)
		if len(got) > 0 {
			seen++
		}
	}
	if seen != 3 {
		t.Fatalf("update transmitted %d times, want 3", seen)
	}
	if b.Len() != 0 {
		t.Fatalf("buffer not retired: %d", b.Len())
	}
}

func TestGossipBufferPriorityOrder(t *testing.T) {
	b := NewBuffer(0)
	b.Add(Update{NodeID: idN(1), Incarnation: 1, State: StateAlive}, 5)
	b.Add(Update{NodeID: idN(2), Incarnation: 1, State: StateDead}, 5)
	b.Add(Update{NodeID: idN(3), Incarnation: 1, State: StateSuspect}, 5)
	got := b.Pick(1)
	if len(got) != 1 || got[0].State != StateDead {
		t.Fatalf("highest-priority pick = %+v, want Dead", got)
	}
}

func TestGossipBufferBoundedAndReplaces(t *testing.T) {
	b := NewBuffer(2)
	b.Add(Update{NodeID: idN(1), Incarnation: 1, State: StateAlive}, 5)
	b.Add(Update{NodeID: idN(2), Incarnation: 1, State: StateAlive}, 5)
	b.Add(Update{NodeID: idN(3), Incarnation: 1, State: StateDead}, 5)
	if b.Len() != 2 {
		t.Fatalf("buffer exceeded cap: %d", b.Len())
	}
	// Replacing an existing node ID does not grow the buffer.
	b.Add(Update{NodeID: idN(3), Incarnation: 2, State: StateDead}, 5)
	if b.Len() != 2 {
		t.Fatalf("replacement grew the buffer: %d", b.Len())
	}
}

func TestCodecRoundTrip(t *testing.T) {
	env := Envelope{
		Kind:           KindPingReq,
		Seq:            0xDEADBEEF,
		Target:         idN(9),
		TargetEndpoint: netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, 2}), 4242),
		Updates: []Update{
			{NodeID: idN(1), Incarnation: 7, Epoch: 3, State: StateSuspect, Endpoint: netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 9}), 9000)},
			{NodeID: idN(2), Incarnation: 1, State: StateAlive},
			{NodeID: idN(3), Incarnation: 99, State: StateLeft, Endpoint: netip.AddrPortFrom(netip.IPv6Loopback(), 1234)},
		},
	}
	raw := Encode(env)
	got, ok := Decode(raw)
	if !ok {
		t.Fatal("decode failed on a valid envelope")
	}
	if got.Kind != env.Kind || got.Seq != env.Seq || got.Target != env.Target {
		t.Fatalf("header mismatch: %+v", got)
	}
	if got.TargetEndpoint != env.TargetEndpoint {
		t.Fatalf("target endpoint mismatch: %v != %v", got.TargetEndpoint, env.TargetEndpoint)
	}
	if len(got.Updates) != len(env.Updates) {
		t.Fatalf("update count %d, want %d", len(got.Updates), len(env.Updates))
	}
	for i := range env.Updates {
		if got.Updates[i] != env.Updates[i] {
			t.Fatalf("update %d: %+v != %+v", i, got.Updates[i], env.Updates[i])
		}
	}
}

func TestCodecMTUBudget(t *testing.T) {
	p := DefaultParams()
	updates := make([]Update, p.MaxPiggyback)
	for i := range updates {
		updates[i] = Update{
			NodeID:      idN(byte(i)),
			Incarnation: ^uint64(0),
			State:       StateLeft,
			Endpoint:    netip.AddrPortFrom(netip.IPv6Loopback(), 65535),
		}
	}
	env := Envelope{Kind: KindPingReq, Seq: 1, Target: idN(0xFF), TargetEndpoint: netip.AddrPortFrom(netip.IPv6Loopback(), 1), Updates: updates}
	raw := Encode(env)
	if len(raw) > transport.MaxPlaintext {
		t.Fatalf("worst-case envelope %d bytes exceeds MaxPlaintext %d", len(raw), transport.MaxPlaintext)
	}
}

// TestCodecNegativeNoPanicNoOveralloc feeds malformed frames and asserts a
// cheap drop with no panic.
func TestCodecNegativeNoPanicNoOveralloc(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x02, KindPing},                       // bad version
		{swimVersion, 0xFF},                    // unknown kind
		{swimVersion, KindPing},                // truncated before seq
		{swimVersion, KindPing, 0, 0, 0, 1},    // seq present, missing updateCount
		{swimVersion, KindPing, 0, 0, 0, 1, 1}, // updateCount=1 but no update body
		{swimVersion, KindPingReq, 0, 0, 0, 1}, // pingreq missing target
		// updateCount claims the hard cap+1 -> cheap reject.
		append([]byte{swimVersion, KindPing, 0, 0, 0, 1, byte(MaxUpdatesPerFrame + 1)}, bytes.Repeat([]byte{0}, 10)...),
		// A valid-looking header with a huge updateCount byte (255) but no bodies.
		{swimVersion, KindPing, 0, 0, 0, 1, 255},
	}
	for i, c := range cases {
		if _, ok := Decode(c); ok {
			t.Fatalf("case %d: malformed frame decoded as valid", i)
		}
	}
	// Fuzz random bytes: must never panic.
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 5000; i++ {
		n := rng.Intn(80)
		b := make([]byte, n)
		rng.Read(b)
		_, _ = Decode(b)
	}
}

func TestSuspicionTimeoutScalesAndClamps(t *testing.T) {
	p := DefaultParams()
	// Small N clamps to the floor (4T).
	if got := p.SuspicionTimeout(1); got != time.Duration(p.SuspFloorMult)*p.T {
		t.Fatalf("N=1 suspicion = %v, want floor %v", got, time.Duration(p.SuspFloorMult)*p.T)
	}
	// Large N clamps to the ceiling (8T).
	if got := p.SuspicionTimeout(1_000_000); got != time.Duration(p.SuspCeilMult)*p.T {
		t.Fatalf("large-N suspicion = %v, want ceil %v", got, time.Duration(p.SuspCeilMult)*p.T)
	}
	// Monotonic non-decreasing in N.
	prev := time.Duration(0)
	for n := 1; n <= 10000; n *= 10 {
		cur := p.SuspicionTimeout(n)
		if cur < prev {
			t.Fatalf("suspicion timeout decreased at N=%d: %v < %v", n, cur, prev)
		}
		prev = cur
	}
	if p.RetransmitCount(1) < 1 {
		t.Fatal("retransmit count must be >= 1")
	}
}

var _ = identity.NodeID{}
