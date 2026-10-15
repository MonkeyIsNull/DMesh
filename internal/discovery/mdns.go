package discovery

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
	zeroconf "github.com/libp2p/zeroconf/v2"
)

// TXT record keys advertised over mDNS. The X25519 static is deliberately NOT
// advertised: under Noise_XX the static is learned and authenticated in-band,
// so publishing it would be a redundant stable-identifier leak.
const (
	txtKeyID    = "id"
	txtKeyLabel = "label"
	txtKeyVer   = "v"
)

// MDNS is the production Discovery backed by zeroconf/v2.
type MDNS struct {
	mu     sync.Mutex
	server *zeroconf.Server
}

// NewMDNS returns an mDNS-backed Discovery.
func NewMDNS() *MDNS { return &MDNS{} }

// Advertise registers this node's service until ctx is canceled. The instance
// name is the full 52-char base32 node ID (one DNS label), maximizing per-LAN
// uniqueness so zeroconf's probe/conflict rename rarely fires.
func (m *MDNS) Advertise(ctx context.Context, self Self) error {
	txt := []string{
		txtKeyID + "=" + self.NodeID,
		txtKeyLabel + "=" + self.Label,
		txtKeyVer + "=" + strconv.Itoa(self.ProtoVersion),
	}
	server, err := zeroconf.Register(self.NodeID, ServiceType, Domain, self.Port, txt, nil)
	if err != nil {
		return fmt.Errorf("discovery: mdns register: %w", err)
	}
	m.mu.Lock()
	m.server = server
	m.mu.Unlock()

	<-ctx.Done()
	server.Shutdown()
	return nil
}

// Browse returns a channel of PeerHints discovered on the LAN until ctx is
// canceled.
func (m *MDNS) Browse(ctx context.Context) (<-chan PeerHint, error) {
	entries := make(chan *zeroconf.ServiceEntry, 16)
	out := make(chan PeerHint, 16)

	if err := zeroconf.Browse(ctx, ServiceType, Domain, entries); err != nil {
		return nil, fmt.Errorf("discovery: mdns browse: %w", err)
	}

	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case e, ok := <-entries:
				if !ok {
					return
				}
				if hint, ok := hintFromEntry(e); ok {
					select {
					case out <- hint:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	return out, nil
}

// Close shuts down any active advertisement.
func (m *MDNS) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.server != nil {
		m.server.Shutdown()
		m.server = nil
	}
	return nil
}

// hintFromEntry converts a zeroconf ServiceEntry into a PeerHint, parsing the
// TXT records and building dial targets from the entry's addresses and port.
// It returns ok=false for an entry that carries no usable node ID or address.
func hintFromEntry(e *zeroconf.ServiceEntry) (PeerHint, bool) {
	txt := parseTXT(e.Text)
	id := txt[txtKeyID]
	if id == "" {
		// Fall back to the instance name, which we set to the node ID.
		id = e.Instance
	}
	if _, err := identity.ParseNodeID(id); err != nil {
		return PeerHint{}, false
	}
	ver := ProtoVersion
	if v, err := strconv.Atoi(txt[txtKeyVer]); err == nil {
		ver = v
	}
	addrs := selectAddrs(e)
	if len(addrs) == 0 {
		return PeerHint{}, false
	}
	return PeerHint{
		NodeID:       id,
		Label:        txt[txtKeyLabel],
		Addrs:        addrs,
		ProtoVersion: ver,
	}, true
}

// selectAddrs builds dial targets from a ServiceEntry, preferring routable
// IPv4, then global IPv6, and skipping zoneless link-local IPv6 (fe80::/10),
// which cannot be dialed without a scope. Blindly taking address index 0 would
// mis-dial multi-homed hosts.
func selectAddrs(e *zeroconf.ServiceEntry) []netip.AddrPort {
	port := uint16(e.Port)
	var v4, v6 []netip.AddrPort
	for _, ip := range e.AddrIPv4 {
		if a, ok := netip.AddrFromSlice(ip.To4()); ok {
			v4 = append(v4, netip.AddrPortFrom(a, port))
		}
	}
	for _, ip := range e.AddrIPv6 {
		a, ok := netip.AddrFromSlice(ip.To16())
		if !ok {
			continue
		}
		if a.Is4In6() {
			continue
		}
		if a.IsLinkLocalUnicast() && a.Zone() == "" {
			continue // unroutable without a scope id
		}
		v6 = append(v6, netip.AddrPortFrom(a, port))
	}
	return append(v4, v6...)
}

// parseTXT turns "k=v" TXT strings into a map.
func parseTXT(txt []string) map[string]string {
	m := make(map[string]string, len(txt))
	for _, kv := range txt {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}
