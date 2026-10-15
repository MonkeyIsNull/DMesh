package discovery

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
	zeroconf "github.com/libp2p/zeroconf/v2"
)

func sampleNodeID(t *testing.T) string {
	t.Helper()
	id, err := identity.Generate("")
	if err != nil {
		t.Fatal(err)
	}
	return id.NodeID().String()
}

// TestMDNSSmoke is a real-multicast smoke test gated behind DMESH_MDNS_E2E=1.
// CI never sets it, so multicast/hardware and the macOS Local Network prompt
// are never exercised in automated runs.
func TestMDNSSmoke(t *testing.T) {
	if os.Getenv("DMESH_MDNS_E2E") != "1" {
		t.Skip("set DMESH_MDNS_E2E=1 to run the real-mDNS smoke test")
	}
	self := Self{
		NodeID:       sampleNodeID(t),
		Label:        "smoke",
		Port:         49999,
		ProtoVersion: ProtoVersion,
	}
	m := NewMDNS()
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { _ = m.Advertise(ctx, self) }()

	browser := NewMDNS()
	defer browser.Close()
	ch, err := browser.Browse(ctx)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case h := <-ch:
		t.Logf("discovered: %+v", h)
	case <-ctx.Done():
		t.Log("no peer discovered within timeout (environment-dependent)")
	}
}

// TestSelectAddrsSkipsZonelessLinkLocal unit-tests address selection without
// any multicast: routable IPv4 is preferred and zoneless link-local IPv6 is
// skipped. This part of the mDNS path is CI-safe.
func TestSelectAddrsSkipsZonelessLinkLocal(t *testing.T) {
	e := &zeroconf.ServiceEntry{}
	e.Port = 5000
	e.AddrIPv4 = []net.IP{net.IPv4(192, 168, 1, 50)}
	e.AddrIPv6 = []net.IP{net.ParseIP("fe80::1"), net.ParseIP("2001:db8::1")}

	addrs := selectAddrs(e)
	if len(addrs) != 2 {
		t.Fatalf("got %d addrs, want 2 (v4 + global v6, link-local skipped): %v", len(addrs), addrs)
	}
	if addrs[0] != netip.MustParseAddrPort("192.168.1.50:5000") {
		t.Fatalf("first addr = %v, want routable IPv4 first", addrs[0])
	}
	for _, a := range addrs {
		if a.Addr().IsLinkLocalUnicast() && a.Addr().Zone() == "" {
			t.Fatalf("zoneless link-local not skipped: %v", a)
		}
	}
}

func TestHintFromEntrySelfAndParsing(t *testing.T) {
	e := &zeroconf.ServiceEntry{}
	e.Instance = "inst"
	e.Port = 6000
	e.AddrIPv4 = []net.IP{net.IPv4(10, 0, 0, 1)}
	e.Text = []string{
		"id=" + sampleNodeID(t),
		"label=node-a",
		"v=1",
	}
	hint, ok := hintFromEntry(e)
	if !ok {
		t.Fatal("valid entry rejected")
	}
	if hint.Label != "node-a" || hint.ProtoVersion != 1 {
		t.Fatalf("parsed hint = %+v", hint)
	}

	// An entry whose TXT id is not a valid node ID is dropped.
	bad := &zeroconf.ServiceEntry{}
	bad.Port = 6000
	bad.AddrIPv4 = []net.IP{net.IPv4(10, 0, 0, 1)}
	bad.Text = []string{"id=not-valid"}
	if _, ok := hintFromEntry(bad); ok {
		t.Fatal("entry with an invalid node ID accepted")
	}
}
