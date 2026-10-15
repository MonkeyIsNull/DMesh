package swim

import (
	"math/rand"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
)

// Detector is the per-period failure-detector bookkeeping: a shuffled
// round-robin cursor over the probeable members and the current period's
// pending probe. It is pure state the node loop drives through the three phases
// (StartPeriod at t=0, Indirect at t=T/3, Expire at t=T). It holds no clock, no
// sockets, and no knowledge of which members are reachable — the loop supplies
// the probeable set each period.
type Detector struct {
	order  []identity.NodeID
	cursor int

	cur     probe
	hasProb bool
}

type probe struct {
	target identity.NodeID
	seq    uint32
	acked  bool
	// indirect records that the indirect (ping-req) phase already ran, so it is
	// not repeated.
	indirect bool
}

// NewDetector returns an empty detector.
func NewDetector() *Detector { return &Detector{} }

// StartPeriod picks the next probe target by round-robin over a freshly
// shuffled member list (reshuffling on wrap), using seq as the correlation
// token for this period's ping. It returns ok=false when there is nothing
// probeable. The caller passes the current probeable set each period; targets
// no longer probeable are skipped.
func (d *Detector) StartPeriod(probeable []identity.NodeID, seq uint32, rng *rand.Rand) (identity.NodeID, bool) {
	d.hasProb = false
	if len(probeable) == 0 {
		d.order = nil
		d.cursor = 0
		return identity.NodeID{}, false
	}
	set := make(map[identity.NodeID]struct{}, len(probeable))
	for _, id := range probeable {
		set[id] = struct{}{}
	}
	// Advance the cursor to the next still-probeable member, reshuffling when the
	// shuffled order is exhausted or stale.
	for attempts := 0; attempts < 2; attempts++ {
		if d.cursor >= len(d.order) {
			d.reshuffle(probeable, rng)
		}
		for d.cursor < len(d.order) {
			cand := d.order[d.cursor]
			d.cursor++
			if _, ok := set[cand]; ok {
				d.cur = probe{target: cand, seq: seq}
				d.hasProb = true
				return cand, true
			}
		}
		// Exhausted the current order without a hit; force a reshuffle and retry.
		d.cursor = len(d.order)
	}
	return identity.NodeID{}, false
}

func (d *Detector) reshuffle(probeable []identity.NodeID, rng *rand.Rand) {
	d.order = append(d.order[:0], probeable...)
	// Fisher-Yates with the injected RNG for deterministic tests.
	for i := len(d.order) - 1; i > 0; i-- {
		var j int
		if rng != nil {
			j = rng.Intn(i + 1)
		}
		d.order[i], d.order[j] = d.order[j], d.order[i]
	}
	d.cursor = 0
}

// Indirect returns the current target and seq if it is still unacked and the
// indirect phase has not yet run, marking it run.
func (d *Detector) Indirect() (identity.NodeID, uint32, bool) {
	if !d.hasProb || d.cur.acked || d.cur.indirect {
		return identity.NodeID{}, 0, false
	}
	d.cur.indirect = true
	return d.cur.target, d.cur.seq, true
}

// Expire returns the current target if it ended the period unacked (the
// failure-detector verdict to apply a Suspect), then clears the probe.
func (d *Detector) Expire() (identity.NodeID, bool) {
	if !d.hasProb {
		return identity.NodeID{}, false
	}
	target := d.cur.target
	acked := d.cur.acked
	d.hasProb = false
	d.cur = probe{}
	if acked {
		return identity.NodeID{}, false
	}
	return target, true
}

// Ack records an ack for seq (direct ack or relayed ping-req ack), canceling
// the pending probe if it matches.
func (d *Detector) Ack(seq uint32) {
	if d.hasProb && d.cur.seq == seq {
		d.cur.acked = true
	}
}

// AckFrom records liveness from a specific member (any decrypted frame from it),
// canceling the pending probe if that member is the current target. This is
// probe bookkeeping only; it never writes roster state.
func (d *Detector) AckFrom(id identity.NodeID) {
	if d.hasProb && d.cur.target == id {
		d.cur.acked = true
	}
}

// Target returns the current probe target and whether a probe is pending (for
// tests).
func (d *Detector) Target() (identity.NodeID, bool) {
	if !d.hasProb {
		return identity.NodeID{}, false
	}
	return d.cur.target, true
}
