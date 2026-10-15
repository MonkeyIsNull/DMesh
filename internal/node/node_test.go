package node

import (
	"context"
	"crypto/rand"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/clock"
	"github.com/MonkeyIsNull/DMesh/internal/discovery"
	"github.com/MonkeyIsNull/DMesh/internal/identity"
	"github.com/MonkeyIsNull/DMesh/internal/transport"
)

func mustPSK(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// loopbackHint builds a static discovery hint pointing at a node's loopback
// endpoint (the node binds 0.0.0.0 but is reachable via 127.0.0.1).
func loopbackHint(id identity.NodeID, port uint16) discovery.PeerHint {
	return discovery.PeerHint{
		NodeID:       id.String(),
		Addrs:        []netip.AddrPort{netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port)},
		ProtoVersion: discovery.ProtoVersion,
	}
}

type testNode struct {
	n    *Node
	id   *identity.Identity
	conn *transport.UDPConn
	disc *discovery.Static
}

func newTestNode(t *testing.T, label string, psk []byte, policy transport.TrustPolicy, enforce bool) *testNode {
	t.Helper()
	id, err := identity.Generate(label)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.ListenUDP(0)
	if err != nil {
		t.Fatal(err)
	}
	disc := discovery.NewStatic()
	n, err := New(Config{
		Identity:         id,
		NetworkPSK:       psk,
		Policy:           policy,
		Discovery:        disc,
		Conn:             conn,
		Clock:            clock.Real{},
		EnforceAllowList: enforce,
		SendGreeting:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &testNode{n: n, id: id, conn: conn, disc: disc}
}

func (tn *testNode) port() uint16 { return tn.conn.LocalAddr().Port() }

func waitConnected(t *testing.T, n *Node, peer identity.NodeID, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, p := range n.Snapshot() {
			if p.State == StateConnected && p.HasID && p.NodeID == peer {
				return true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// waitLabel polls until the node has learned the given label for peer (sent via
// HELLO just after connect), or the timeout elapses.
func waitLabel(t *testing.T, n *Node, peer identity.NodeID, want string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, p := range n.Snapshot() {
			if p.NodeID == peer && p.Label == want {
				return true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func countConnected(n *Node, peer identity.NodeID) int {
	c := 0
	for _, p := range n.Snapshot() {
		if p.State == StateConnected && p.HasID && p.NodeID == peer {
			c++
		}
	}
	return c
}

func TestTwoNodesConnectOverLoopback(t *testing.T) {
	psk := mustPSK(t)
	a := newTestNode(t, "alice", psk, transport.AllowList(nil, false), false)
	b := newTestNode(t, "bob", psk, transport.AllowList(nil, false), false)
	defer a.conn.Close()
	defer b.conn.Close()

	// Each node learns the other via static discovery.
	a.disc.Push(loopbackHint(b.id.NodeID(), b.port()))
	b.disc.Push(loopbackHint(a.id.NodeID(), a.port()))

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = a.n.Run(ctx) }()
	go func() { defer wg.Done(); _ = b.n.Run(ctx) }()

	if !waitConnected(t, a.n, b.id.NodeID(), 5*time.Second) {
		t.Error("A never reached connected with B")
	}
	if !waitConnected(t, b.n, a.id.NodeID(), 5*time.Second) {
		t.Error("B never reached connected with A")
	}
	// Exactly one stable session per peer identity (collapse/idempotency).
	if c := countConnected(a.n, b.id.NodeID()); c != 1 {
		t.Errorf("A has %d connected sessions to B, want 1", c)
	}
	if c := countConnected(b.n, a.id.NodeID()); c != 1 {
		t.Errorf("B has %d connected sessions to A, want 1", c)
	}
	// Labels were exchanged via HELLO. The HELLO frame is sent just AFTER the
	// handshake completes, so reaching Connected does not guarantee it has been
	// processed yet; poll for it rather than reading once (the single-read race
	// was an intermittent full-package -race failure).
	if !waitLabel(t, a.n, b.id.NodeID(), "bob", 5*time.Second) {
		t.Error("A did not learn B's label via HELLO")
	}

	cancel()
	wg.Wait()
}

func TestSelfFilter(t *testing.T) {
	psk := mustPSK(t)
	a := newTestNode(t, "alice", psk, transport.AllowList(nil, false), false)
	defer a.conn.Close()

	// Feed the node its OWN hint; it must never dial itself.
	a.disc.Push(loopbackHint(a.id.NodeID(), a.port()))

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = a.n.Run(ctx) }()

	time.Sleep(500 * time.Millisecond)
	if len(a.n.Snapshot()) != 0 {
		t.Errorf("node created a peer from its own advertisement: %+v", a.n.Snapshot())
	}
	cancel()
	wg.Wait()
}

func TestWrongNetworkKeyNeverConnects(t *testing.T) {
	a := newTestNode(t, "alice", mustPSK(t), transport.AllowList(nil, false), false)
	b := newTestNode(t, "bob", mustPSK(t), transport.AllowList(nil, false), false) // different PSK
	defer a.conn.Close()
	defer b.conn.Close()

	a.disc.Push(loopbackHint(b.id.NodeID(), b.port()))
	b.disc.Push(loopbackHint(a.id.NodeID(), a.port()))

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = a.n.Run(ctx) }()
	go func() { defer wg.Done(); _ = b.n.Run(ctx) }()

	// Neither side may ever reach connected: the wrong key fails the handshake.
	if waitConnected(t, a.n, b.id.NodeID(), 2*time.Second) {
		t.Error("A connected to B despite a mismatched network key")
	}
	if countConnected(b.n, a.id.NodeID()) != 0 {
		t.Error("B connected to A despite a mismatched network key")
	}
	cancel()
	wg.Wait()
}

func TestAllowListGateRejectsUntrusted(t *testing.T) {
	psk := mustPSK(t)
	// Both nodes enforce a trust-only allow-list that excludes the other, so
	// the handshake completes (PSK valid) but the gate tears it down.
	a := newTestNode(t, "alice", psk, transport.AllowList(nil, true), true)
	b := newTestNode(t, "bob", psk, transport.AllowList(nil, true), true)
	defer a.conn.Close()
	defer b.conn.Close()

	a.disc.Push(loopbackHint(b.id.NodeID(), b.port()))
	b.disc.Push(loopbackHint(a.id.NodeID(), a.port()))

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = a.n.Run(ctx) }()
	go func() { defer wg.Done(); _ = b.n.Run(ctx) }()

	if waitConnected(t, a.n, b.id.NodeID(), 2*time.Second) {
		t.Error("A admitted an untrusted peer past the allow-list gate")
	}
	if countConnected(b.n, a.id.NodeID()) != 0 {
		t.Error("B admitted an untrusted peer past the allow-list gate")
	}
	cancel()
	wg.Wait()
}

func TestAllowListTrustedConnects(t *testing.T) {
	psk := mustPSK(t)
	a := newTestNode(t, "alice", psk, nil, false)
	b := newTestNode(t, "bob", psk, nil, false)
	defer a.conn.Close()
	defer b.conn.Close()

	// A trusts exactly B; B trusts exactly A. The gate admits the trusted ID,
	// keyed on the authenticated identity.
	a.n.policy = transport.AllowList(map[identity.NodeID]struct{}{b.id.NodeID(): {}}, true)
	a.n.enforce = true
	b.n.policy = transport.AllowList(map[identity.NodeID]struct{}{a.id.NodeID(): {}}, true)
	b.n.enforce = true

	a.disc.Push(loopbackHint(b.id.NodeID(), b.port()))
	b.disc.Push(loopbackHint(a.id.NodeID(), a.port()))

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = a.n.Run(ctx) }()
	go func() { defer wg.Done(); _ = b.n.Run(ctx) }()

	if !waitConnected(t, a.n, b.id.NodeID(), 5*time.Second) {
		t.Error("A did not connect to its trusted peer B")
	}
	if !waitConnected(t, b.n, a.id.NodeID(), 5*time.Second) {
		t.Error("B did not connect to its trusted peer A")
	}
	cancel()
	wg.Wait()
}

// TestTrustKeysOffAuthenticatedIdentity proves the gate keys off the
// Noise-authenticated Ed25519 identity, never the spoofable mDNS TXT id: a hint
// advertising a trusted-looking (but wrong) node ID for B's real endpoint does
// NOT grant B trust, because the handshake authenticates B's real key.
func TestTrustKeysOffAuthenticatedIdentity(t *testing.T) {
	psk := mustPSK(t)
	// A trusts only a fabricated node ID (not B's real one).
	fake, _ := identity.Generate("imposter")
	a := newTestNode(t, "alice", psk, nil, false)
	b := newTestNode(t, "bob", psk, transport.AllowList(nil, false), false)
	defer a.conn.Close()
	defer b.conn.Close()
	a.n.policy = transport.AllowList(map[identity.NodeID]struct{}{fake.NodeID(): {}}, true)
	a.n.enforce = true

	// Push a hint for B's REAL endpoint but claiming the fabricated node ID.
	a.disc.Push(discovery.PeerHint{
		NodeID:       fake.NodeID().String(),
		Addrs:        []netip.AddrPort{netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), b.port())},
		ProtoVersion: discovery.ProtoVersion,
	})
	b.disc.Push(loopbackHint(a.id.NodeID(), a.port()))

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = a.n.Run(ctx) }()
	go func() { defer wg.Done(); _ = b.n.Run(ctx) }()

	// A authenticates B's REAL id, which is not the trusted fake id => rejected.
	if waitConnected(t, a.n, b.id.NodeID(), 2*time.Second) {
		t.Error("A trusted B via a spoofed TXT id instead of the authenticated key")
	}
	if waitConnected(t, a.n, fake.NodeID(), 500*time.Millisecond) {
		t.Error("A connected under the fabricated identity")
	}
	cancel()
	wg.Wait()
}

func TestConcurrentRendererSnapshot(t *testing.T) {
	psk := mustPSK(t)
	a := newTestNode(t, "alice", psk, transport.AllowList(nil, false), false)
	b := newTestNode(t, "bob", psk, transport.AllowList(nil, false), false)
	defer a.conn.Close()
	defer b.conn.Close()

	a.disc.Push(loopbackHint(b.id.NodeID(), b.port()))
	b.disc.Push(loopbackHint(a.id.NodeID(), a.port()))

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = a.n.Run(ctx) }()
	go func() { defer wg.Done(); _ = b.n.Run(ctx) }()

	// Hammer the renderer snapshot WHILE handshakes are in flight so -race
	// covers the renderer/peer-table access, not a quiesced read.
	stop := make(chan struct{})
	var rwg sync.WaitGroup
	rwg.Add(1)
	go func() {
		defer rwg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = a.n.Snapshot()
				_ = b.n.Snapshot()
			}
		}
	}()

	connected := waitConnected(t, a.n, b.id.NodeID(), 5*time.Second)
	close(stop)
	rwg.Wait()
	if !connected {
		t.Error("nodes did not connect while the renderer was running")
	}
	cancel()
	wg.Wait()
}
