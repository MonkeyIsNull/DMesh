package transport

import (
	"errors"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
)

// The permissioned membership gate has two real layers:
//
//  1. PRIMARY (in this package, because it feeds Noise): a 32-byte pre-shared
//     network key mixed as the Noise PSK at psk0. A wrong or absent key fails
//     the AEAD on handshake message 1 - the cheapest rejection. The node MUST
//     fail closed: with no key configured it refuses to start rather than
//     falling back to a keyless plain-XX handshake.
//
//  2. SECONDARY: an allow-list checked AFTER the handshake completes, against
//     the Noise-authenticated Ed25519 identity (never the spoofable mDNS TXT).
//     That decision is a policy callback the node owns, aligning the seam with
//     the later signed-invite/CA package.

// ErrNoNetworkKey indicates no network key is configured; the node must refuse
// to start (fail closed).
var ErrNoNetworkKey = errors.New("transport: no network key configured (fail closed; run 'dmesh network-key gen')")

// ValidatePSK checks that a network key is present and exactly the required
// length. A nil/empty key is the fail-closed error.
func ValidatePSK(psk []byte) error {
	if len(psk) == 0 {
		return ErrNoNetworkKey
	}
	if len(psk) != 32 {
		return errors.New("transport: network key must be 32 bytes")
	}
	return nil
}

// TrustDecision is the post-handshake policy verdict for an authenticated peer.
type TrustDecision int

const (
	// TrustAccept admits the peer.
	TrustAccept TrustDecision = iota
	// TrustReject tears the session down with no application data exchanged.
	TrustReject
)

// TrustPolicy decides whether an authenticated peer may join. It is always
// called with the node ID RE-DERIVED from the Noise-authenticated static via
// the verified binding signature - never a discovery hint.
type TrustPolicy func(peer identity.NodeID) TrustDecision

// AllowList builds a TrustPolicy from a set of trusted node IDs. An empty set
// means trust-on-first-use (accept any peer that proved the network key),
// unless trustOnly is set, in which case an empty set rejects everyone.
func AllowList(trusted map[identity.NodeID]struct{}, trustOnly bool) TrustPolicy {
	return func(peer identity.NodeID) TrustDecision {
		if len(trusted) == 0 && !trustOnly {
			return TrustAccept // TOFU
		}
		if _, ok := trusted[peer]; ok {
			return TrustAccept
		}
		return TrustReject
	}
}
