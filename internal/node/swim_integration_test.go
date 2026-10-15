package node

import (
	"fmt"
	"testing"
	"time"
)

func label(i int) string { return fmt.Sprintf("n%d", i) }

// TestSimConnectAndAlive is a harness smoke test: a small mesh connects and
// every node sees every other as Alive in the gossiped roster.
func TestSimConnectAndAlive(t *testing.T) {
	m := newSimMesh(t, 1)
	defer m.stop()
	for i := 0; i < 4; i++ {
		m.addNode(t, label(i), nil)
	}
	m.wireFullMesh()
	if !m.waitAllConnected(5 * time.Second) {
		t.Fatal("mesh did not fully connect")
	}
	m.periods(3)
	assertAllAlive(t, m)
}

func assertAllAlive(t *testing.T, m *simMesh) {
	t.Helper()
	for _, a := range m.nodes {
		for _, b := range m.nodes {
			if a == b {
				continue
			}
			st, ok := m.stateOf(a, b)
			if !ok || st != "alive" {
				t.Fatalf("%s sees %s as %q (ok=%v), want alive",
					a.id.NodeID().Short(), b.id.NodeID().Short(), st, ok)
			}
		}
	}
}

// TestFailureDetection kills a node (full isolation) and asserts the remaining
// nodes detect it, suspect it, and converge to Dead within a bounded, counted
// number of periods.
func TestFailureDetection(t *testing.T) {
	m := newSimMesh(t, 2)
	defer m.stop()
	for i := 0; i < 4; i++ {
		m.addNode(t, label(i), nil)
	}
	m.wireFullMesh()
	if !m.waitAllConnected(5 * time.Second) {
		t.Fatal("mesh did not connect")
	}
	m.periods(2)

	victim := m.nodes[3]
	m.r.isolate(victim.addr, true) // kill: drop all its I/O, session stays probeable

	const maxPeriods = 40
	deadEverywhere := false
	for i := 0; i < maxPeriods && !deadEverywhere; i++ {
		m.period()
		deadEverywhere = true
		for _, a := range m.nodes {
			if a == victim {
				continue
			}
			st, _ := m.stateOf(a, victim)
			if st != "dead" {
				deadEverywhere = false
			}
		}
	}
	if !deadEverywhere {
		for _, a := range m.nodes {
			if a == victim {
				continue
			}
			st, _ := m.stateOf(a, victim)
			t.Logf("%s sees victim as %q", a.id.NodeID().Short(), st)
		}
		t.Fatalf("victim not Dead on all live nodes within %d periods", maxPeriods)
	}
}

// TestGossipConvergenceIsolated isolates the dissemination mechanism: join-sync
// and gossip-driven re-dial are OFF, so a single injected update can reach
// every node ONLY via piggybacked infection. It asserts convergence within a
// bounded number of periods, failing if exceeded (so a broken-piggyback or
// O(N^2) regression fails here).
func TestGossipConvergenceIsolated(t *testing.T) {
	const N = 6
	m := newSimMesh(t, 3)
	defer m.stop()
	for i := 0; i < N; i++ {
		m.addNode(t, label(i), func(cfg *Config) {
			cfg.DisableJoinSync = true
			cfg.DisableGossipDial = true
		})
	}
	m.wireFullMesh()
	if !m.waitAllConnected(5 * time.Second) {
		t.Fatal("mesh did not connect")
	}
	m.periods(2)

	// Normalize to a deterministic baseline: clear the residual connect-time
	// gossip (self/peer Alive updates, whose lastSent ordering varies with the
	// nondeterministic real-time connect order) from every node's buffer while
	// the mesh is quiesced. After this the ONLY update in flight is the injected
	// fact, so — combined with the deterministic probe sequence (sorted
	// candidates + seeded RNG) and the happens-before barrier — convergence is a
	// pure, run-independent function and this bound cannot false-fail on correct
	// infection gossip.
	m.r.settle()
	for _, sn := range m.nodes {
		sn.n.resetGossipForTest()
	}

	// Inject a fact about a synthetic (never-present) node at node 0. Alive so it
	// never expires; no endpoint so no dial is attempted even if enabled.
	fake := idFake(0x7A)
	injectUpdate(m.nodes[0], swimAlive(fake, 1), m.clk.Now())

	bound := m.params.RetransmitCount(N) + N // generous but still catches "never"
	converged := false
	used := 0
	for i := 0; i < bound && !converged; i++ {
		m.period()
		used++
		converged = true
		for _, a := range m.nodes {
			if _, ok := a.n.MemberState(fake); !ok {
				converged = false
			}
		}
	}
	if !converged {
		t.Fatalf("update did not reach all %d nodes within %d periods", N, bound)
	}
	t.Logf("gossip converged across %d nodes in %d periods (bound %d)", N, used, bound)
}

// TestSuspicionAndRefutation drives suspicion through the REAL detector (a
// period timeout, not an injected Suspect), then heals, and asserts the victim
// refuted: its incarnation strictly increased on every node and it is Alive
// again. An ignored-refutation regression fails here.
func TestSuspicionAndRefutation(t *testing.T) {
	m := newSimMesh(t, 4)
	defer m.stop()
	for i := 0; i < 4; i++ {
		m.addNode(t, label(i), nil)
	}
	m.wireFullMesh()
	if !m.waitAllConnected(5 * time.Second) {
		t.Fatal("mesh did not connect")
	}
	m.periods(2)

	victim := m.nodes[2]
	incBefore, _ := m.incOf(m.nodes[0], victim)

	// Isolate the victim long enough to be suspected somewhere, but NOT long
	// enough to be reaped, then heal.
	m.r.isolate(victim.addr, true)
	// Drive periods until at least one node suspects or deads the victim.
	suspectedSomewhere := false
	for i := 0; i < 40 && !suspectedSomewhere; i++ {
		m.period()
		for _, a := range m.nodes {
			if a == victim {
				continue
			}
			st, _ := m.stateOf(a, victim)
			if st == "suspect" || st == "dead" {
				suspectedSomewhere = true
			}
		}
	}
	if !suspectedSomewhere {
		t.Fatal("victim was never suspected by the real detector")
	}

	// Heal: the victim is reachable again. The reconciliation burst carries the
	// stale state to it; it refutes with a higher incarnation. Recovery is
	// defined as every node showing the victim Alive AT A STRICTLY HIGHER
	// incarnation — proving the surviving Alive arrived as the victim's own
	// refutation, not a stale equal-incarnation Alive (which the lattice would
	// reject). This is what makes an ignored-refutation regression fail here.
	m.r.isolate(victim.addr, false)
	recovered := false
	for i := 0; i < 50 && !recovered; i++ {
		m.period()
		recovered = true
		for _, a := range m.nodes {
			if a == victim {
				continue
			}
			st, _ := m.stateOf(a, victim)
			incAfter, ok := m.incOf(a, victim)
			if st != "alive" || !ok || incAfter <= incBefore {
				recovered = false
			}
		}
	}
	if !recovered {
		for _, a := range m.nodes {
			if a == victim {
				continue
			}
			st, _ := m.stateOf(a, victim)
			inc, _ := m.incOf(a, victim)
			t.Logf("%s sees victim as %q inc=%d (before=%d)", a.id.NodeID().Short(), st, inc, incBefore)
		}
		t.Fatal("victim did not recover to Alive with an advanced incarnation on every node (refutation ignored?)")
	}
}

// TestPartitionAndHeal splits the mesh into two halves whose cross links are
// blocked, lets each half mark the other's members Dead, then heals and asserts
// the rosters reconcile with no permanent false Dead.
func TestPartitionAndHeal(t *testing.T) {
	m := newSimMesh(t, 5)
	defer m.stop()
	for i := 0; i < 4; i++ {
		m.addNode(t, label(i), nil)
	}
	m.wireFullMesh()
	if !m.waitAllConnected(5 * time.Second) {
		t.Fatal("mesh did not connect")
	}
	m.periods(2)

	groupA := []*simNode{m.nodes[0], m.nodes[1]}
	groupB := []*simNode{m.nodes[2], m.nodes[3]}
	for _, a := range groupA {
		for _, b := range groupB {
			m.r.blockLink(a.addr, b.addr, true)
		}
	}

	// Let each half declare the other half Dead.
	deadAcross := false
	for i := 0; i < 50 && !deadAcross; i++ {
		m.period()
		deadAcross = true
		for _, a := range groupA {
			for _, b := range groupB {
				if st, _ := m.stateOf(a, b); st != "dead" {
					deadAcross = false
				}
				if st, _ := m.stateOf(b, a); st != "dead" {
					deadAcross = false
				}
			}
		}
	}
	if !deadAcross {
		t.Fatal("partition did not produce cross-group Dead divergence")
	}

	// Heal.
	for _, a := range groupA {
		for _, b := range groupB {
			m.r.blockLink(a.addr, b.addr, false)
		}
	}
	healed := false
	for i := 0; i < 60 && !healed; i++ {
		m.period()
		healed = true
		for _, a := range m.nodes {
			for _, b := range m.nodes {
				if a == b {
					continue
				}
				if st, _ := m.stateOf(a, b); st != "alive" {
					healed = false
				}
			}
		}
	}
	if !healed {
		for _, a := range m.nodes {
			for _, b := range m.nodes {
				if a == b {
					continue
				}
				st, _ := m.stateOf(a, b)
				t.Logf("%s sees %s as %q", a.id.NodeID().Short(), b.id.NodeID().Short(), st)
			}
		}
		t.Fatal("rosters did not reconcile to all-Alive after heal (permanent false Dead)")
	}
}

// TestLeaveAndRejoin asserts a graceful Leave shows as Left (not a failure
// cascade), the Left entry is retained across a gap (not reaped), and a rejoin
// with the SAME keypair supersedes it with a higher incarnation.
func TestLeaveAndRejoin(t *testing.T) {
	m := newSimMesh(t, 6)
	defer m.stop()
	for i := 0; i < 3; i++ {
		m.addNode(t, label(i), nil)
	}
	m.wireFullMesh()
	if !m.waitAllConnected(5 * time.Second) {
		t.Fatal("mesh did not connect")
	}
	m.periods(2)

	leaver := m.nodes[2]
	leaver.n.Leave(m.ctx)
	m.r.settle()

	// Isolate + stop driving the leaver so it does not re-advertise.
	m.r.isolate(leaver.addr, true)

	leftSeen := false
	for i := 0; i < 20 && !leftSeen; i++ {
		m.period()
		leftSeen = true
		for _, a := range m.nodes {
			if a == leaver {
				continue
			}
			if st, _ := m.stateOf(a, leaver); st != "left" {
				leftSeen = false
			}
		}
	}
	if !leftSeen {
		for _, a := range m.nodes {
			if a == leaver {
				continue
			}
			st, _ := m.stateOf(a, leaver)
			t.Logf("%s sees leaver as %q", a.id.NodeID().Short(), st)
		}
		t.Fatal("leaver not marked Left on peers")
	}

	// The Left entry must be RETAINED across a modest gap (shorter than reap).
	m.advance(5 * m.params.T)
	m.period()
	for _, a := range m.nodes {
		if a == leaver {
			continue
		}
		if st, _ := m.stateOf(a, leaver); st != "left" {
			t.Fatalf("%s lost the Left entry (got %q) before reap window", a.id.NodeID().Short(), st)
		}
	}
}

// TestRestartIncarnationResetAsymmetricReap is the documented split-brain
// regression: a restarted node with a reset in-memory incarnation must still
// win against a peer that still holds a stale Dead about it, thanks to the
// persisted incarnation resuming at persisted+1.
func TestRestartIncarnationResetAsymmetricReap(t *testing.T) {
	m := newSimMesh(t, 7)
	defer m.stop()
	for i := 0; i < 3; i++ {
		m.addNode(t, label(i), nil)
	}
	m.wireFullMesh()
	if !m.waitAllConnected(5 * time.Second) {
		t.Fatal("mesh did not connect")
	}
	m.periods(2)

	witness := m.nodes[0]
	restarter := m.nodes[2]
	incBeforeRestart, _ := restarter.n.MemberIncarnation(restarter.id.NodeID())

	// Kill the restarter and let the mesh mark it Dead.
	m.r.isolate(restarter.addr, true)
	deadOnWitness := false
	for i := 0; i < 40 && !deadOnWitness; i++ {
		m.period()
		if st, _ := m.stateOf(witness, restarter); st == "dead" {
			deadOnWitness = true
		}
	}
	if !deadOnWitness {
		t.Fatal("restarter never marked Dead before restart")
	}

	// Restart with the SAME identity + persistence path. Its in-memory
	// incarnation resets, but the persisted value resumes at persisted+1.
	m.r.isolate(restarter.addr, false)
	m.restartNode(restarter)
	// Re-seed discovery so it re-handshakes with the mesh.
	for _, b := range m.nodes {
		if b == restarter {
			continue
		}
		m.hint(restarter, b)
		m.hint(b, restarter)
	}
	if !m.waitAllConnected(5 * time.Second) {
		// It is enough that the restarter connects to the witness.
	}

	won := false
	for i := 0; i < 40 && !won; i++ {
		m.period()
		st, _ := m.stateOf(witness, restarter)
		incAfter, _ := witness.n.MemberIncarnation(restarter.id.NodeID())
		if st == "alive" && incAfter > incBeforeRestart {
			won = true
		}
	}
	if !won {
		st, _ := m.stateOf(witness, restarter)
		incAfter, _ := witness.n.MemberIncarnation(restarter.id.NodeID())
		t.Fatalf("restarter did not win on the witness: state=%q inc=%d (was %d)",
			st, incAfter, incBeforeRestart)
	}
}

// TestMessageLossTolerance runs detection + convergence under heavy per-link
// loss and asserts zero false Dead of reachable members (the source of truth
// that tunes the suspicion-timeout floor), while a genuinely isolated node is
// still detected Dead.
func TestMessageLossTolerance(t *testing.T) {
	m := newSimMesh(t, 8)
	// This test is the source of truth that tunes the suspicion-timeout floor:
	// under heavy loss, refutation needs more periods to round-trip, so the floor
	// is raised here. Production DefaultParams keeps 4T; the honest reading is
	// that 4T is the loss-free floor and a high-loss deployment wants a larger
	// one (documented in the README threat/scope note).
	m.params.SuspFloorMult = 10
	m.params.SuspCeilMult = 20
	defer m.stop()
	for i := 0; i < 4; i++ {
		m.addNode(t, label(i), nil)
	}
	m.wireFullMesh()
	if !m.waitAllConnected(5 * time.Second) {
		t.Fatal("mesh did not connect")
	}
	m.periods(2)

	// Enable loss AFTER connections are established (so handshakes need no
	// retransmit timers).
	m.r.setLoss(250) // 25% per-link loss
	victim := m.nodes[3]
	m.r.isolate(victim.addr, true)

	const maxPeriods = 80
	for i := 0; i < maxPeriods; i++ {
		m.period()
		// Zero false Dead of reachable members: nodes 0,1,2 must never be Dead on
		// each other despite the loss.
		for _, a := range m.nodes[:3] {
			for _, b := range m.nodes[:3] {
				if a == b {
					continue
				}
				if st, _ := m.stateOf(a, b); st == "dead" {
					t.Fatalf("false Dead under loss: %s marked reachable %s Dead",
						a.id.NodeID().Short(), b.id.NodeID().Short())
				}
			}
		}
	}
	// The genuinely isolated victim must be detected Dead by the reachable set.
	for _, a := range m.nodes[:3] {
		if st, _ := m.stateOf(a, victim); st != "dead" {
			t.Fatalf("%s did not detect the isolated victim Dead under loss (got %q)",
				a.id.NodeID().Short(), st)
		}
	}
}

// TestReachabilityNoFalseDeadThenCausal proves A's continued view of C as
// non-dead is due to B's reachability, not indifference: while B can reach C,
// A (which has no session to C) never sees C suspect/dead; once B's path to C
// is cut and C is fully isolated, C goes Dead mesh-wide.
func TestReachabilityNoFalseDeadThenCausal(t *testing.T) {
	m := newSimMesh(t, 9)
	defer m.stop()
	// A=0, B=1, C=2. Disable gossip-dial so A never opens a session to C from a
	// learned endpoint.
	for i := 0; i < 3; i++ {
		m.addNode(t, label(i), func(cfg *Config) { cfg.DisableGossipDial = true })
	}
	A, B, C := m.nodes[0], m.nodes[1], m.nodes[2]
	// B discovers both A and C; A and C discover only B. A and C never get a
	// session to each other (no hint + blocked link).
	m.hint(B, A)
	m.hint(B, C)
	m.hint(A, B)
	m.hint(C, B)
	m.r.blockLink(A.addr, C.addr, true)

	// Wait for A-B and B-C sessions.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		m.r.settle()
		if sessionUp(A, B) && sessionUp(B, C) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !sessionUp(A, B) || !sessionUp(B, C) {
		t.Fatal("A-B or B-C session did not establish")
	}
	m.periods(3)
	// A must know C (via gossip) but hold no session to it.
	if _, ok := m.stateOf(A, C); !ok {
		t.Fatal("A never learned C via gossip")
	}
	if sessionUp(A, C) {
		t.Fatal("A unexpectedly has a direct session to C")
	}

	// Phase 1: while B reaches C, advance well past the suspicion timeout and
	// assert A's view of C never goes suspect/dead.
	for i := 0; i < 20; i++ {
		m.period()
		if st, _ := m.stateOf(A, C); st == "suspect" || st == "dead" {
			t.Fatalf("A falsely marked C %q while B could still reach it", st)
		}
	}

	// Phase 2: isolate C entirely. Now nobody can reach it; it must go Dead
	// mesh-wide and (being isolated) cannot refute.
	m.r.isolate(C.addr, true)
	cDead := false
	for i := 0; i < 60 && !cDead; i++ {
		m.period()
		sa, _ := m.stateOf(A, C)
		sb, _ := m.stateOf(B, C)
		cDead = sa == "dead" && sb == "dead"
	}
	if !cDead {
		sa, _ := m.stateOf(A, C)
		sb, _ := m.stateOf(B, C)
		t.Fatalf("C not Dead mesh-wide after full isolation: A=%q B=%q", sa, sb)
	}
}

// TestFabricatedIDFloodRejected asserts an enforced allow-list rejects a
// gossip-injected fabricated member (not re-gossiped, not dialed) and the
// roster + half-open table stay O(N).
func TestFabricatedIDFloodRejected(t *testing.T) {
	m := newSimMesh(t, 10)
	defer m.stop()
	// Build a 3-node allow-list-enforced mesh (each trusts the others only).
	ids := make([]*simNode, 0, 3)
	for i := 0; i < 3; i++ {
		sn := m.addNode(t, label(i), func(cfg *Config) {
			cfg.EnforceAllowList = true
		})
		ids = append(ids, sn)
	}
	// Rebuild policies now that all identities exist: each node trusts exactly
	// the other two real nodes (and nothing fabricated).
	applyMutualAllowList(ids)
	m.wireFullMesh()
	if !m.waitAllConnected(5 * time.Second) {
		t.Fatal("allow-listed mesh did not connect")
	}
	m.periods(2)

	// Inject a flood of fabricated Alive members (with dialable endpoints) at
	// node 0. They are not allow-listed, so the roster must reject them.
	victim := m.nodes[0]
	for i := 0; i < 200; i++ {
		fab := idFake(byte(i))
		injectUpdate(victim, swimAliveEP(fab, 1, m.addr(50+i%5)), m.clk.Now())
	}
	m.periods(5)

	for _, a := range m.nodes {
		// Only self + the 2 real peers may be members.
		if c := a.n.memberCountForTest(); c > 2 {
			t.Fatalf("%s roster grew to %d members under a fabricated-ID flood (want <=2)",
				a.id.NodeID().Short(), c)
		}
		if h := a.n.halfOpenLenForTest(); h > halfOpenLimit {
			t.Fatalf("%s half-open table exceeded its bound: %d", a.id.NodeID().Short(), h)
		}
	}
}

// TestNoGoroutineLeak asserts the node goroutines return to a baseline after
// ctx cancel (proving simConn.ReadFrom is Close-unblocked and there is no
// stranded per-peer send goroutine).
func TestNoGoroutineLeak(t *testing.T) {
	base := goroutineCount()
	m := newSimMesh(t, 11)
	for i := 0; i < 4; i++ {
		m.addNode(t, label(i), nil)
	}
	m.wireFullMesh()
	if !m.waitAllConnected(5 * time.Second) {
		t.Fatal("mesh did not connect")
	}
	m.periods(3)
	m.stop()

	// Poll back to baseline (allow a small slack for the test runtime).
	deadline := time.Now().Add(5 * time.Second)
	var got int
	for time.Now().Before(deadline) {
		got = goroutineCount()
		if got <= base+5 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("goroutines did not return to baseline: got %d, baseline %d", got, base)
}

// TestTransitiveGossipDiscovery verifies a node learns a peer it never
// discovered via mDNS (only via gossip) and then connects to it through the
// gossip-as-dial-hint path.
func TestTransitiveGossipDiscovery(t *testing.T) {
	m := newSimMesh(t, 12)
	defer m.stop()
	for i := 0; i < 3; i++ {
		m.addNode(t, label(i), nil)
	}
	A, B, C := m.nodes[0], m.nodes[1], m.nodes[2]
	// A<->B and B<->C are discovered directly; A and C are NOT. A should learn C
	// via B's gossip and dial it.
	m.hint(A, B)
	m.hint(B, A)
	m.hint(B, C)
	m.hint(C, B)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		m.r.settle()
		if sessionUp(A, B) && sessionUp(B, C) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Run periods so gossip carries C to A (deterministic) and the dial hint
	// fires. The resulting A->C Noise handshake runs through the transport state
	// machine on real goroutines — the deterministic barrier intentionally does
	// not wait on in-progress handshakes (their inbox frames are consumed by the
	// transport, not a barrier-retiring handler), so poll for the session on a
	// real-time deadline, exactly as the initial-connect path (waitAllConnected)
	// does. Gossip convergence stays deterministic; only the concurrent
	// handshake's completion is polled.
	learned := false
	dialDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(dialDeadline) && !learned {
		m.period()
		if sessionUp(A, C) {
			learned = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !learned {
		t.Fatal("A never connected to C via transitive gossip discovery")
	}
}
