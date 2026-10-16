package node

import (
	"net/netip"
	"testing"
	"time"
)

// TestSeedPeersConnectWithoutDiscovery proves the static --peer seed dialer
// connects two nodes with NO discovery hints: discovery yields nothing, and the
// only path by which the nodes find each other is one node seeding the other's
// address. The seed dialer rides the injected clock, so waitAllConnected's clock
// advances drive its retries deterministically.
func TestSeedPeersConnectWithoutDiscovery(t *testing.T) {
	m := newSimMesh(t, 7)
	defer m.stop()

	// Node 0 is plain (registered first so its address exists when it is dialed).
	a := m.addNode(t, label(0), nil)
	// Node 1 seeds node 0's address directly; neither node receives any hint.
	b := m.addNode(t, label(1), func(cfg *Config) {
		cfg.SeedPeers = []netip.AddrPort{a.addr}
	})
	_ = b

	if !m.waitAllConnected(5 * time.Second) {
		t.Fatal("seed-dialed mesh did not connect without discovery")
	}
}
