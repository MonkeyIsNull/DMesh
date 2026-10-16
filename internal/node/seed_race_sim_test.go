package node

import (
	"net/netip"
	"testing"
	"time"
)

// TestSeedAndHintConcurrentDialSameAddr is a regression test for the
// single-writer violation in the seed dialer. Node B targets node A by TWO
// concurrent paths at once: a discovery hint for A (driven on the event loop via
// handleHint) AND SeedPeers=[A.addr] (driven by the seed dialer). Both paths
// touch byAddr[A.addr].
//
// Under the OLD code the seed dialer called startInitiator directly from its own
// goroutine, so that byAddr write raced the loop's unlocked byAddr reads/writes
// in the hint path — a data race, and a possible fatal "concurrent map read and
// map write". With seed dials routed through n.seedDial and performed on the
// loop by handleSeedDial, both writers are the single loop goroutine, so the run
// is clean under -race. The nodes must still connect.
func TestSeedAndHintConcurrentDialSameAddr(t *testing.T) {
	m := newSimMesh(t, 11)
	defer m.stop()

	// Node A is registered first so its address exists when B dials it.
	a := m.addNode(t, label(0), nil)
	// Node B seeds A's address directly AND is handed a discovery hint for A, so
	// the seed path and the hint path race toward the same byAddr entry. A short
	// fallback-dial delay (the sim default is 24h) keeps the connection
	// deterministic regardless of which path reaches the loop first: if B loses
	// the hint election it records A as discovered (which suppresses the seed
	// dial), and the fallback-dial timer then upgrades that entry to an initiator.
	b := m.addNode(t, label(1), func(cfg *Config) {
		cfg.SeedPeers = []netip.AddrPort{a.addr}
		cfg.FallbackDialDelay = 200 * time.Millisecond
	})
	m.hint(b, a)

	if !m.waitAllConnected(5 * time.Second) {
		t.Fatal("seed+hint mesh did not connect")
	}
}
