package transport

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
)

// PacketConn is the datagram socket the node reads from and writes to. It is an
// interface so tests can substitute an in-memory lossy/reordering conn for real
// UDP. net.UDPConn is safe for concurrent ReadFromUDPAddrPort/WriteToUDPAddrPort.
type PacketConn interface {
	WriteTo(b []byte, addr netip.AddrPort) error
	ReadFrom(b []byte) (int, netip.AddrPort, error)
	LocalAddr() netip.AddrPort
	Close() error
}

// UDPConn is the production PacketConn over net.UDPConn.
type UDPConn struct {
	c *net.UDPConn
}

// ListenUDP binds a UDP socket on the given port (0 = ephemeral) on all
// interfaces.
func ListenUDP(port int) (*UDPConn, error) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return nil, fmt.Errorf("transport: listen udp: %w", err)
	}
	return &UDPConn{c: c}, nil
}

// WriteTo sends a datagram to addr.
func (u *UDPConn) WriteTo(b []byte, addr netip.AddrPort) error {
	_, err := u.c.WriteToUDPAddrPort(b, addr)
	return err
}

// ReadFrom reads one datagram.
func (u *UDPConn) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	return u.c.ReadFromUDPAddrPort(b)
}

// LocalAddr returns the bound address.
func (u *UDPConn) LocalAddr() netip.AddrPort {
	return u.c.LocalAddr().(*net.UDPAddr).AddrPort()
}

// Close closes the socket.
func (u *UDPConn) Close() error { return u.c.Close() }

// AddrSender adapts a PacketConn and a fixed peer address into a Sender for the
// handshake driver.
type AddrSender struct {
	Conn PacketConn
	Addr netip.AddrPort
}

// Send implements Sender.
func (a AddrSender) Send(b []byte) error { return a.Conn.WriteTo(b, a.Addr) }

// HalfOpenTable bounds the number of in-progress (half-open) handshakes. Rather
// than a hard cap (which would itself be a lockout DoS under a valid-PSK msg1
// flood), it evicts the oldest entry when full.
type HalfOpenTable struct {
	mu    sync.Mutex
	limit int
	seq   uint64
	items map[netip.AddrPort]uint64
}

// NewHalfOpenTable returns a table bounded at limit entries.
func NewHalfOpenTable(limit int) *HalfOpenTable {
	return &HalfOpenTable{limit: limit, items: make(map[netip.AddrPort]uint64)}
}

// Admit records a half-open handshake for addr, evicting the oldest if full.
// It returns the addr evicted (if any) so the caller can cancel it.
func (t *HalfOpenTable) Admit(addr netip.AddrPort) (evicted netip.AddrPort, didEvict bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.items[addr]; ok {
		t.seq++
		t.items[addr] = t.seq
		return
	}
	if len(t.items) >= t.limit {
		var oldestAddr netip.AddrPort
		var oldestSeq uint64 = ^uint64(0)
		for a, s := range t.items {
			if s < oldestSeq {
				oldestSeq, oldestAddr = s, a
			}
		}
		delete(t.items, oldestAddr)
		evicted, didEvict = oldestAddr, true
	}
	t.seq++
	t.items[addr] = t.seq
	return
}

// Remove drops a half-open entry (handshake completed or failed).
func (t *HalfOpenTable) Remove(addr netip.AddrPort) {
	t.mu.Lock()
	delete(t.items, addr)
	t.mu.Unlock()
}

// Len returns the current number of half-open entries (for bounds assertions).
func (t *HalfOpenTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.items)
}
