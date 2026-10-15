package swim

import (
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
)

func idN(b byte) identity.NodeID {
	var n identity.NodeID
	n[0] = b
	n[31] = b
	return n
}

func ep(port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), port)
}

func newTestRoster(self identity.NodeID) *Roster {
	return NewRoster(RosterConfig{Self: self, SelfInc: 1, Params: DefaultParams()})
}

// TestLatticeConvergesIndependentOfOrder applies a fixed set of updates in many
// random permutations and asserts the final stored tuple is identical: the
// merge is commutative, associative, and idempotent.
func TestLatticeConvergesIndependentOfOrder(t *testing.T) {
	self := idN(0xFF)
	target := idN(0x01)
	updates := []Update{
		{NodeID: target, Incarnation: 1, State: StateAlive, Endpoint: ep(100)},
		{NodeID: target, Incarnation: 1, State: StateSuspect},
		{NodeID: target, Incarnation: 2, State: StateAlive},
		{NodeID: target, Incarnation: 2, State: StateSuspect},
		{NodeID: target, Incarnation: 2, State: StateDead},
		{NodeID: target, Incarnation: 3, State: StateAlive},
		{NodeID: target, Incarnation: 3, State: StateLeft},
		{NodeID: target, Incarnation: 3, State: StateDead}, // loses to Left at eq inc
		{NodeID: target, Incarnation: 3, State: StateSuspect},
	}
	// Expected winner: highest incarnation 3, highest rank at 3 is Left.
	wantInc, wantState := uint64(3), StateLeft

	now := time.Unix(0, 0)
	rng := rand.New(rand.NewSource(42))
	for trial := 0; trial < 200; trial++ {
		perm := append([]Update(nil), updates...)
		rng.Shuffle(len(perm), func(i, j int) { perm[i], perm[j] = perm[j], perm[i] })
		r := newTestRoster(self)
		for _, u := range perm {
			r.Apply(u, now)
		}
		m := r.members[target]
		if m == nil {
			t.Fatalf("trial %d: member missing", trial)
		}
		if m.Incarnation != wantInc || m.State != wantState {
			t.Fatalf("trial %d: got (%d,%s), want (%d,%s)", trial, m.Incarnation, m.State, wantInc, wantState)
		}
	}
}

func TestLeftBeatsDeadAtEqualIncarnation(t *testing.T) {
	r := newTestRoster(idN(0xFF))
	now := time.Unix(0, 0)
	target := idN(2)
	r.Apply(Update{NodeID: target, Incarnation: 5, State: StateDead}, now)
	res := r.Apply(Update{NodeID: target, Incarnation: 5, State: StateLeft}, now)
	if !res.Changed {
		t.Fatal("Left at equal incarnation should override Dead")
	}
	// The reverse must not override.
	r.Apply(Update{NodeID: target, Incarnation: 5, State: StateDead}, now)
	if r.members[target].State != StateLeft {
		t.Fatalf("Dead overrode Left at equal incarnation: %s", r.members[target].State)
	}
}

func TestLeftSuppressesReSuspicion(t *testing.T) {
	r := newTestRoster(idN(0xFF))
	now := time.Unix(0, 0)
	target := idN(3)
	r.Apply(Update{NodeID: target, Incarnation: 7, State: StateLeft}, now)
	res := r.Apply(Update{NodeID: target, Incarnation: 7, State: StateSuspect}, now)
	if res.Changed {
		t.Fatal("equal-incarnation Suspect must not override Left")
	}
	// A genuine rejoin (higher incarnation Alive) wins.
	res = r.Apply(Update{NodeID: target, Incarnation: 8, State: StateAlive}, now)
	if !res.Changed || r.members[target].State != StateAlive {
		t.Fatal("higher-incarnation Alive should supersede Left (rejoin)")
	}
}

func TestAliveStrictlyGreaterToOverride(t *testing.T) {
	r := newTestRoster(idN(0xFF))
	now := time.Unix(0, 0)
	target := idN(4)
	r.Apply(Update{NodeID: target, Incarnation: 2, State: StateSuspect}, now)
	// Equal-incarnation Alive must NOT clear the suspicion (load-bearing: only
	// the subject's own higher-incarnation refutation clears it).
	res := r.Apply(Update{NodeID: target, Incarnation: 2, State: StateAlive}, now)
	if res.Changed || r.members[target].State != StateSuspect {
		t.Fatal("equal-incarnation Alive wrongly cleared Suspect")
	}
	// Strictly-greater Alive clears it.
	res = r.Apply(Update{NodeID: target, Incarnation: 3, State: StateAlive}, now)
	if !res.Changed || r.members[target].State != StateAlive {
		t.Fatal("higher-incarnation Alive failed to clear Suspect")
	}
}

func TestDuplicateSuspectDoesNotResetTimer(t *testing.T) {
	r := newTestRoster(idN(0xFF))
	t0 := time.Unix(0, 0)
	target := idN(5)
	r.Apply(Update{NodeID: target, Incarnation: 1, State: StateAlive}, t0)
	s0 := t0.Add(1 * time.Second)
	r.Apply(Update{NodeID: target, Incarnation: 1, State: StateSuspect}, s0)
	// A duplicate equal-incarnation suspect later must not advance StateChange.
	r.Apply(Update{NodeID: target, Incarnation: 1, State: StateSuspect}, s0.Add(3*time.Second))
	if !r.members[target].StateChange.Equal(s0) {
		t.Fatalf("duplicate suspect reset the suspicion timer: %v != %v", r.members[target].StateChange, s0)
	}
}

func TestSelfRefutation(t *testing.T) {
	self := idN(0xAA)
	persisted := uint64(0)
	r := NewRoster(RosterConfig{
		Self: self, SelfInc: 1, Params: DefaultParams(),
		Persist: func(v uint64) error { persisted = v; return nil },
	})
	now := time.Unix(0, 0)
	res := r.Apply(Update{NodeID: self, Incarnation: 1, State: StateSuspect}, now)
	if res.Refutation == nil {
		t.Fatal("expected a refutation for a current-incarnation self-suspect")
	}
	if r.SelfInc() != 2 {
		t.Fatalf("selfInc = %d, want 2", r.SelfInc())
	}
	if res.Refutation.State != StateAlive || res.Refutation.Incarnation != 2 {
		t.Fatalf("refutation = (%d,%s), want (2,alive)", res.Refutation.Incarnation, res.Refutation.State)
	}
	if persisted != 2 {
		t.Fatalf("persist got %d, want 2", persisted)
	}
}

func TestSelfIncJumpCapRejectsForgedInflation(t *testing.T) {
	self := idN(0xAB)
	r := NewRoster(RosterConfig{Self: self, SelfInc: 1, Params: DefaultParams()})
	now := time.Unix(0, 0)
	res := r.Apply(Update{NodeID: self, Incarnation: 1_000_000, State: StateSuspect}, now)
	if !res.Forged || res.Refutation != nil {
		t.Fatal("a self-suspect far above selfInc must be rejected as forged")
	}
	if r.SelfInc() != 1 {
		t.Fatalf("forged inflation advanced selfInc to %d", r.SelfInc())
	}
}

func TestSuspectToDeadAfterTimeout(t *testing.T) {
	r := newTestRoster(idN(0xFF))
	t0 := time.Unix(0, 0)
	target := idN(6)
	r.Apply(Update{NodeID: target, Incarnation: 1, State: StateAlive}, t0)
	su := r.LocalSuspect(target, t0.Add(time.Second))
	if su == nil {
		t.Fatal("LocalSuspect returned nil for an alive member")
	}
	susp := r.params.SuspicionTimeout(r.Size())
	// Before the timeout: no promotion.
	if got := r.Tick(t0.Add(time.Second + susp - time.Nanosecond)); len(got) != 0 {
		t.Fatalf("premature suspect->dead: %+v", got)
	}
	// At/after the timeout: promoted to Dead and gossiped.
	got := r.Tick(t0.Add(time.Second + susp))
	if len(got) != 1 || got[0].State != StateDead {
		t.Fatalf("expected one Dead update, got %+v", got)
	}
	if r.members[target].State != StateDead {
		t.Fatalf("member not Dead: %s", r.members[target].State)
	}
}

func TestReapAndTombstoneRejectsZombie(t *testing.T) {
	r := newTestRoster(idN(0xFF))
	t0 := time.Unix(0, 0)
	target := idN(7)
	r.Apply(Update{NodeID: target, Incarnation: 4, State: StateDead}, t0)
	reap := r.params.ReapAfter(r.Size())
	r.Tick(t0.Add(reap))
	if _, ok := r.members[target]; ok {
		t.Fatal("dead member was not reaped")
	}
	if r.TombstoneCount() != 1 {
		t.Fatalf("expected 1 tombstone, got %d", r.TombstoneCount())
	}
	// Replay of a stale Dead at or below the tombstone incarnation: no zombie.
	res := r.Apply(Update{NodeID: target, Incarnation: 4, State: StateDead}, t0.Add(reap+time.Second))
	if res.Changed || len(r.members) != 0 {
		t.Fatal("replayed stale Dead resurrected a reaped member")
	}
	// A genuine rejoin (higher incarnation) clears the tombstone.
	res = r.Apply(Update{NodeID: target, Incarnation: 5, State: StateAlive}, t0.Add(reap+2*time.Second))
	if !res.Changed || r.members[target] == nil {
		t.Fatal("higher-incarnation rejoin failed to clear the tombstone")
	}
	if r.TombstoneCount() != 0 {
		t.Fatalf("tombstone not cleared on rejoin: %d", r.TombstoneCount())
	}
}

func TestTombstoneTTLEviction(t *testing.T) {
	r := newTestRoster(idN(0xFF))
	t0 := time.Unix(0, 0)
	target := idN(8)
	r.Apply(Update{NodeID: target, Incarnation: 1, State: StateDead}, t0)
	reap := r.params.ReapAfter(r.Size())
	r.Tick(t0.Add(reap))
	if r.TombstoneCount() != 1 {
		t.Fatalf("want 1 tombstone, got %d", r.TombstoneCount())
	}
	r.Tick(t0.Add(reap + r.params.TombstoneTTL))
	if r.TombstoneCount() != 0 {
		t.Fatalf("tombstone not TTL-evicted: %d", r.TombstoneCount())
	}
}

func TestAllowListGateRejectsAndDoesNotGossip(t *testing.T) {
	allowed := idN(1)
	denied := idN(2)
	r := NewRoster(RosterConfig{
		Self: idN(0xFF), SelfInc: 1, Params: DefaultParams(),
		Allowed: func(id identity.NodeID) bool { return id == allowed },
	})
	now := time.Unix(0, 0)
	res := r.Apply(Update{NodeID: denied, Incarnation: 1, State: StateAlive, Endpoint: ep(1)}, now)
	if res.Changed || res.Regossip != nil || r.members[denied] != nil {
		t.Fatal("denied node was admitted or re-gossiped")
	}
	res = r.Apply(Update{NodeID: allowed, Incarnation: 1, State: StateAlive, Endpoint: ep(2)}, now)
	if !res.Changed || r.members[allowed] == nil {
		t.Fatal("allowed node was rejected")
	}
}
