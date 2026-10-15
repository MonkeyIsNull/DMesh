package node

import (
	"context"
	"net/netip"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
	"github.com/MonkeyIsNull/DMesh/internal/transport"
)

// LinkState is a peer's connection state for the status view.
type LinkState int

const (
	// StateDiscovered: learned from discovery, not yet handshaking.
	StateDiscovered LinkState = iota
	// StateHandshaking: a Noise handshake is in progress.
	StateHandshaking
	// StateConnected: handshake done, identity verified, trusted, session live.
	StateConnected
	// StatePaused: reserved for the durable-session milestone (transport
	// dropped, session not torn down). Not entered in v0.1.
	StatePaused
	// StateFailed: handshake or trust check failed.
	StateFailed
)

// String renders a link state for the status table.
func (s LinkState) String() string {
	switch s {
	case StateDiscovered:
		return "discovered"
	case StateHandshaking:
		return "handshaking"
	case StateConnected:
		return "connected"
	case StatePaused:
		return "paused"
	case StateFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// peer is a node's record of another node. It is created keyed by remote UDP
// address while handshaking, then merged/re-keyed by the authenticated Ed25519
// node ID once the identity binding verifies - the exact seam the
// identity-not-address roaming milestone hangs on. Only the node event loop
// mutates a peer's fields.
type peer struct {
	addr      netip.AddrPort
	inbox     chan []byte // event loop -> this peer's driver goroutine
	cancel    context.CancelFunc
	initiator bool

	localIndex uint32

	// authenticated identity (zero until the binding verifies)
	nodeID identity.NodeID
	label  string

	state    LinkState
	lastSeen time.Time

	// sess is the live transport session, published to the loop by the driver
	// over sessReady once the handshake completes. The loop owns this field (so
	// all peer-field writes stay single-writer) and Seals SWIM frames directly
	// through it; Session.Seal is itself concurrency-safe, so the loop Sealing
	// alongside the driver's keepalive/runSession is sound.
	sess *transport.Session
}

// PeerView is an immutable snapshot of a peer for the status renderer.
type PeerView struct {
	NodeID   identity.NodeID
	Label    string
	Endpoint netip.AddrPort
	State    LinkState
	LastSeen time.Time
	HasID    bool
}
