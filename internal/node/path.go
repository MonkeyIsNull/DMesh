package node

import (
	"github.com/MonkeyIsNull/DMesh/internal/identity"
	"github.com/MonkeyIsNull/DMesh/internal/nat"
)

// pathKind is how a peer's frames are physically delivered.
type pathKind uint8

const (
	// pathDirect delivers frames straight to the peer's real UDP address. It is
	// the zero value, so an un-annotated peer is direct.
	pathDirect pathKind = iota
	// pathRelay delivers frames wrapped as circData and sealed on the carrier
	// session to a relay node, which forwards them to the peer. A relayed peer is
	// NEVER addressed by its (undialable) pseudo-address; all routing branches on
	// path.kind, never on the address.
	pathRelay
)

// peerPath records how to reach a peer. It is written ONLY by the event loop
// (like every other peer field) and read off-loop ONLY under n.mu, which is the
// invariant sendToPeer relies on to resolve the route race-free.
type peerPath struct {
	kind    pathKind
	relay   identity.NodeID // carrier identity (pathRelay only)
	circuit nat.CircuitID   // circuit id on the relay (pathRelay only)
}

// pathSender adapts a peer into a transport.Sender so the Noise handshake driver
// sends through the single sendToPeer chokepoint (and therefore over the circuit
// for a relayed peer) with no change to the handshake state machine.
type pathSender struct {
	n *Node
	p *peer
}

// Send implements transport.Sender by routing the datagram through sendToPeer.
func (s pathSender) Send(b []byte) error {
	// WriteTo in the sim/real conn never returns a meaningful error for a drop;
	// sendToPeer already treats a missing carrier as a silent drop. Returning nil
	// keeps the handshake driver's retransmit loop in charge of recovery.
	s.n.sendToPeer(s.p, b)
	return nil
}
