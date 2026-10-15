// Package swim is the pure, side-effect-free SWIM membership state machine for
// DMesh v0.2. It implements the SWIM failure detector (ping / ping-req), the
// incarnation-numbered suspicion + refutation logic (with the Lifeguard
// log-scaled suspicion timeout), infection-style gossip dissemination, and a
// replicated roster with reaping + tombstones.
//
// The package is deliberately free of goroutines, sockets, and the clock: every
// method takes `now` and inbound data and returns outbound *actions* (updates
// to gossip, frames to send). All concurrency and I/O live in package node,
// whose single event-loop goroutine owns a Roster and calls into it. This
// mirrors how transport.Session stays a pure cipher object while node owns the
// goroutines around it.
//
// Correctness references (studied, NOT depended on): the SWIM paper (Das,
// Gupta, Motwani 2002) for the failure-detector + infection gossip, the
// Lifeguard paper (Dadgar, Phillips, Currey 2018) for the log-scaled suspicion
// timeout and local-health ideas, and hashicorp/memberlist state.go for the
// concrete merge/refute accept conditions. Honesty note: the base-10 log
// scaling and the λ=4 / suspMult=4 constants below are memberlist's *practical*
// tuning, NOT a result of SWIM's theoretical O(log N) (base e/2) analysis; they
// are validated here by the deterministic loss/partition tests, not asserted
// safe a priori.
package swim

import (
	"math"
	"time"
)

// Params holds every tunable of the SWIM layer. Defaults come from
// DefaultParams; the sim tests override T and the timer-related knobs so the
// injectable clock drives everything deterministically.
type Params struct {
	// T is the protocol period. One direct-ping target is probed per period.
	T time.Duration
	// K is the indirect-probe fan-out (number of relays asked to ping-req).
	K int
	// SuspMult scales the log-N suspicion timeout.
	SuspMult int
	// Lambda scales the log-N gossip retransmit count.
	Lambda int
	// SuspFloorMult and SuspCeilMult clamp the suspicion timeout to
	// [SuspFloorMult*T, SuspCeilMult*T]. The floor is the load-bearing guard
	// against false Dead of a reachable-but-slow member; it is tuned by the
	// loss/partition tests (which assert zero false Dead), not hard-proven safe.
	SuspFloorMult int
	SuspCeilMult  int
	// ReapMult sets how long a Dead/Left entry is kept before reaping, as a
	// multiple of the suspicion timeout.
	ReapMult int
	// MaxPiggyback caps the number of gossip updates piggybacked on one frame,
	// keeping a datagram well under the transport MTU (see codec.go).
	MaxPiggyback int
	// MaxSelfIncJump caps how far above our own incarnation an inbound
	// self-suspicion may claim before we treat it as forged and ignore it. Since
	// only self ever advances self's incarnation, any larger value is provably
	// fabricated.
	MaxSelfIncJump uint64
	// TombstoneTTL bounds how long a reaped member's tombstone is retained to
	// reject replayed stale updates.
	TombstoneTTL time.Duration
	// TombstoneCap bounds the tombstone map (LRU-evicted) so churn stays O(N +
	// recent-churn).
	TombstoneCap int
}

// DefaultParams returns the production parameters (see the §0 decision table in
// the design plan).
func DefaultParams() Params {
	return Params{
		T:              1 * time.Second,
		K:              3,
		SuspMult:       4,
		Lambda:         4,
		SuspFloorMult:  4,
		SuspCeilMult:   8,
		ReapMult:       10,
		MaxPiggyback:   12,
		MaxSelfIncJump: 16,
		TombstoneTTL:   5 * time.Minute,
		TombstoneCap:   1024,
	}
}

// ceilLog10 returns ceil(log10(x)) for x>=1, with ceilLog10(1)=0. It is the
// discrete size scaling used for both the suspicion timeout and the gossip
// retransmit count.
func ceilLog10(x int) int {
	if x <= 1 {
		return 0
	}
	return int(math.Ceil(math.Log10(float64(x))))
}

// SuspicionTimeout returns how long a member may remain Suspect before it is
// locally declared Dead, for a mesh of n known members. It is
// clamp(SuspMult*ceil(log10(n+1))*T, floor, ceil) in the Lifeguard style.
func (p Params) SuspicionTimeout(n int) time.Duration {
	base := time.Duration(p.SuspMult*ceilLog10(n+1)) * p.T
	floor := time.Duration(p.SuspFloorMult) * p.T
	ceil := time.Duration(p.SuspCeilMult) * p.T
	if base < floor {
		base = floor
	}
	if base > ceil {
		base = ceil
	}
	return base
}

// RetransmitCount returns how many times a single gossip update is retransmitted
// before being retired, for a mesh of n known members: ceil(Lambda*log10(n+1)),
// at least 1.
func (p Params) RetransmitCount(n int) int {
	c := int(math.Ceil(float64(p.Lambda) * math.Log10(float64(n+1))))
	if c < 1 {
		return 1
	}
	return c
}

// ReapAfter returns how long a Dead/Left entry is kept before it is reaped into
// a tombstone.
func (p Params) ReapAfter(n int) time.Duration {
	return time.Duration(p.ReapMult) * p.SuspicionTimeout(n)
}
