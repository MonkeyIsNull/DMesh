package swim

import (
	"net/netip"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
)

// MemberState is the liveness/roster state of a member in the SWIM lattice.
type MemberState uint8

const (
	// StateAlive: the member is believed reachable (directly or by proxy).
	StateAlive MemberState = iota
	// StateSuspect: a failure detector round failed; the member has not yet
	// refuted and the suspicion timer is running.
	StateSuspect
	// StateDead: the suspicion timer expired without refutation. Kept a while as
	// a tombstoned-soon entry so a genuine return reconciles.
	StateDead
	// StateLeft: the member announced a graceful departure. Distinguished from
	// Dead so a leave does not read as a failure cascade; suppresses re-suspicion
	// at equal incarnation.
	StateLeft
)

// String renders a member state for the status view.
func (s MemberState) String() string {
	switch s {
	case StateAlive:
		return "alive"
	case StateSuspect:
		return "suspect"
	case StateDead:
		return "dead"
	case StateLeft:
		return "left"
	default:
		return "unknown"
	}
}

// rank is the equal-incarnation precedence of a state: higher rank wins a tie.
// Left > Dead > Suspect > Alive. This single ordering encodes every required
// accept condition (see roster.go merge).
func rank(s MemberState) int {
	switch s {
	case StateAlive:
		return 0
	case StateSuspect:
		return 1
	case StateDead:
		return 2
	case StateLeft:
		return 3
	default:
		return -1
	}
}

// Update is one membership fact about one node, as it travels on the wire
// (piggybacked on SWIM frames) and through the lattice merge.
//
// The triple (NodeID, Incarnation, State) is the entire membership assertion.
// Epoch is a reserved restart/epoch byte carried on the wire now (v0.2 merge
// logic ignores it) so the later signed-update milestone can sign over
// (NodeID, Incarnation, Epoch, State) without a wire-format bump. Endpoint is a
// dial HINT only and may be unreachable from the receiver.
type Update struct {
	NodeID      identity.NodeID
	Incarnation uint64
	Epoch       uint8
	State       MemberState
	Endpoint    netip.AddrPort
}

// precedes reports whether tuple a is strictly below tuple b in the total order
// (higher incarnation wins; on a tie, higher state rank wins). The merge
// accepts an incoming update iff the stored tuple precedes it, which makes the
// merge a max over a total order: commutative, associative, and idempotent, so
// the roster converges independent of update arrival order.
func precedes(aInc uint64, aState MemberState, bInc uint64, bState MemberState) bool {
	if aInc != bInc {
		return aInc < bInc
	}
	return rank(aState) < rank(bState)
}
