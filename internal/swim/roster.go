package swim

import (
	"net/netip"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
)

// Member is the roster's stored record for one non-self node.
type Member struct {
	ID          identity.NodeID
	Incarnation uint64
	Epoch       uint8
	State       MemberState
	Endpoint    netip.AddrPort
	// StateChange is advanced ONLY when the stored tuple strictly advances. It
	// anchors the suspect->dead timer and the reap timer, so a drip of duplicate
	// equal-incarnation suspects can never reset the clock and starve the
	// transition.
	StateChange time.Time
}

// tombstone is the bounded residue of a reaped Dead/Left member: just enough to
// reject a replayed stale update (incarnation <= inc) while a genuine rejoin
// (strictly higher incarnation) clears it.
type tombstone struct {
	inc      uint64
	reapedAt time.Time
	// seq orders tombstones for LRU eviction when the cap is exceeded.
	seq uint64
}

// Roster is the replicated membership table owned by the node event loop. It is
// NOT safe for concurrent use; the loop holds n.mu around every call.
type Roster struct {
	self         identity.NodeID
	selfInc      uint64
	selfEndpoint netip.AddrPort

	members    map[identity.NodeID]*Member
	tombstones map[identity.NodeID]tombstone
	tombSeq    uint64

	params Params

	// persist stores a newly-advanced self incarnation durably (beside the
	// identity). Nil disables persistence (tests that don't exercise restart).
	persist func(uint64) error
	// allowed gates which node IDs may enter the roster. Nil => accept all
	// (trust-on-first-use). When enforced, a rejected update is neither stored
	// nor re-gossiped (no injection, no amplification).
	allowed func(identity.NodeID) bool
}

// ApplyResult reports what one Apply produced for the caller to act on.
type ApplyResult struct {
	// Changed is true iff the stored tuple strictly advanced.
	Changed bool
	// Regossip, if non-nil, is the update to feed into the gossip buffer.
	Regossip *Update
	// Refutation, if non-nil, is a self-Alive update (our own refutation of a
	// stale suspicion about us) to broadcast; selfInc has already been advanced
	// and persisted.
	Refutation *Update
	// Forged is true when an inbound self-update claimed an incarnation beyond
	// the MaxSelfIncJump cap and was discarded (observability only).
	Forged bool
	// LearnedEndpoint, when valid together with Changed, is a newly-learned
	// Alive member's dial hint the loop may feed to discovery.
	LearnedEndpoint netip.AddrPort
}

// RosterConfig configures a new Roster.
type RosterConfig struct {
	Self         identity.NodeID
	SelfInc      uint64
	SelfEndpoint netip.AddrPort
	Params       Params
	Persist      func(uint64) error
	Allowed      func(identity.NodeID) bool
}

// NewRoster builds an empty roster for self at the given starting incarnation.
func NewRoster(cfg RosterConfig) *Roster {
	return &Roster{
		self:         cfg.Self,
		selfInc:      cfg.SelfInc,
		selfEndpoint: cfg.SelfEndpoint,
		members:      make(map[identity.NodeID]*Member),
		tombstones:   make(map[identity.NodeID]tombstone),
		params:       cfg.Params,
		persist:      cfg.Persist,
		allowed:      cfg.Allowed,
	}
}

// SelfInc returns this node's current incarnation.
func (r *Roster) SelfInc() uint64 { return r.selfInc }

// SetAllowed replaces the allow-list gate (used when the trust policy is
// configured after construction).
func (r *Roster) SetAllowed(allowed func(identity.NodeID) bool) { r.allowed = allowed }

// Size returns the number of known members including self; it feeds the
// log-scaled suspicion/retransmit computations.
func (r *Roster) Size() int { return len(r.members) + 1 }

// SelfAlive returns this node's own Alive update (for seeding gossip at start
// and for join-sync bursts).
func (r *Roster) SelfAlive() Update {
	return Update{NodeID: r.self, Incarnation: r.selfInc, State: StateAlive, Endpoint: r.selfEndpoint}
}

// Apply merges one inbound update into the roster, returning what to do next.
// It is the single merge entry point and implements the total-order lattice
// join described in update.go.
func (r *Roster) Apply(u Update, now time.Time) ApplyResult {
	if u.NodeID.IsZero() {
		return ApplyResult{}
	}
	// Allow-list gate: reject (and do not re-gossip) a non-admitted node so a
	// credentialed peer cannot inject a fabricated member or amplify one.
	if r.allowed != nil && u.NodeID != r.self && !r.allowed(u.NodeID) {
		return ApplyResult{}
	}
	if u.NodeID == r.self {
		return r.applySelf(u, now)
	}

	// Tombstone guard: a reaped member stays dead against a replayed stale
	// update; only a strictly-higher incarnation (a genuine rejoin) clears it.
	if t, ok := r.tombstones[u.NodeID]; ok {
		if u.Incarnation <= t.inc {
			return ApplyResult{}
		}
		delete(r.tombstones, u.NodeID)
	}

	m := r.members[u.NodeID]
	if m == nil {
		nm := &Member{
			ID:          u.NodeID,
			Incarnation: u.Incarnation,
			Epoch:       u.Epoch,
			State:       u.State,
			Endpoint:    u.Endpoint,
			StateChange: now,
		}
		r.members[u.NodeID] = nm
		res := ApplyResult{Changed: true, Regossip: ptr(u)}
		if u.State == StateAlive && u.Endpoint.IsValid() {
			res.LearnedEndpoint = u.Endpoint
		}
		return res
	}

	if precedes(m.Incarnation, m.State, u.Incarnation, u.State) {
		prevState := m.State
		m.Incarnation = u.Incarnation
		m.Epoch = u.Epoch
		m.State = u.State
		if u.Endpoint.IsValid() {
			m.Endpoint = u.Endpoint
		}
		m.StateChange = now
		res := ApplyResult{Changed: true, Regossip: ptr(u)}
		// A member that (re)became Alive with a dialable hint and that we may not
		// have a session to is a dial candidate for the loop.
		if u.State == StateAlive && prevState != StateAlive && m.Endpoint.IsValid() {
			res.LearnedEndpoint = m.Endpoint
		}
		return res
	}

	// Not strictly advancing. Fill in a missing endpoint hint opportunistically
	// (does not change the tuple, is not re-gossiped).
	if !m.Endpoint.IsValid() && u.Endpoint.IsValid() {
		m.Endpoint = u.Endpoint
	}
	return ApplyResult{}
}

// applySelf handles an update about ourselves. Self's own state is always
// locally (selfInc, Alive); it is never stored in the members map, so the
// detector never probes self. A stale or forged self-update is discarded; a
// current-or-higher Suspect/Dead/Left triggers refute-adopts-higher.
func (r *Roster) applySelf(u Update, now time.Time) ApplyResult {
	if u.State == StateAlive {
		// An echo of our own Alive; we are the sole authority on it. Ignore.
		return ApplyResult{}
	}
	if u.Incarnation > r.selfInc+r.params.MaxSelfIncJump {
		// Provably forged inflation: only self advances self's incarnation, so a
		// value far beyond ours could not have originated from us.
		return ApplyResult{Forged: true}
	}
	if u.Incarnation >= r.selfInc {
		r.selfInc = u.Incarnation + 1
		if r.persist != nil {
			_ = r.persist(r.selfInc)
		}
		ref := r.SelfAlive()
		return ApplyResult{Refutation: &ref}
	}
	// A stale suspicion about us (incarnation below ours): the sender still holds
	// an out-of-date Suspect/Dead/Left for us at an old incarnation. We do not
	// bump (our current incarnation already dominates it), but we MUST re-assert
	// our current Alive so the stale holder converges — otherwise a peer that
	// deadened us before our last refutation would hold that Dead forever, since
	// our refutation had already retired from the gossip buffer.
	ref := r.SelfAlive()
	return ApplyResult{Refutation: &ref}
}

// Observe records a directly-connected peer as Alive. The incarnation floor of
// 0 is deliberately low: the peer's own Alive gossip (carrying its real
// incarnation) supersedes it, and a stale Dead/Left we hold is only overridden
// by the peer's higher-incarnation refutation, not by this call. It returns an
// update to gossip if the observation changed state.
func (r *Roster) Observe(id identity.NodeID, ep netip.AddrPort, now time.Time) *Update {
	if id == r.self || id.IsZero() {
		return nil
	}
	res := r.Apply(Update{NodeID: id, Incarnation: 0, State: StateAlive, Endpoint: ep}, now)
	// Even when the state did not advance, keep the freshest dial hint.
	if m := r.members[id]; m != nil && ep.IsValid() {
		m.Endpoint = ep
	}
	return res.Regossip
}

// LocalSuspect marks a member Suspect at its current incarnation, as the
// failure detector's verdict at the end of a period. It only fires on an Alive
// member (so a Left/Dead/already-Suspect member is untouched) and returns the
// update to gossip, or nil.
func (r *Roster) LocalSuspect(id identity.NodeID, now time.Time) *Update {
	m := r.members[id]
	if m == nil || m.State != StateAlive {
		return nil
	}
	m.State = StateSuspect
	m.StateChange = now
	u := Update{NodeID: id, Incarnation: m.Incarnation, Epoch: m.Epoch, State: StateSuspect, Endpoint: m.Endpoint}
	return &u
}

// Leave advances self's incarnation, persists it, and returns the Left update
// to flush to peers before shutdown.
func (r *Roster) Leave() Update {
	r.selfInc++
	if r.persist != nil {
		_ = r.persist(r.selfInc)
	}
	return Update{NodeID: r.self, Incarnation: r.selfInc, State: StateLeft, Endpoint: r.selfEndpoint}
}

// Tick runs the once-per-period maintenance: promote expired Suspects to Dead,
// reap long-Dead/Left entries into tombstones, and evict stale tombstones. It
// returns the Dead updates it generated for the loop to gossip.
func (r *Roster) Tick(now time.Time) []Update {
	n := r.Size()
	susp := r.params.SuspicionTimeout(n)
	reap := r.params.ReapAfter(n)

	var out []Update
	for id, m := range r.members {
		if m.State == StateSuspect && now.Sub(m.StateChange) >= susp {
			m.State = StateDead
			m.StateChange = now
			out = append(out, Update{NodeID: id, Incarnation: m.Incarnation, Epoch: m.Epoch, State: StateDead, Endpoint: m.Endpoint})
		}
	}
	for id, m := range r.members {
		if (m.State == StateDead || m.State == StateLeft) && now.Sub(m.StateChange) >= reap {
			r.addTombstone(id, m.Incarnation, now)
			delete(r.members, id)
		}
	}
	for id, t := range r.tombstones {
		if now.Sub(t.reapedAt) >= r.params.TombstoneTTL {
			delete(r.tombstones, id)
		}
	}
	return out
}

// addTombstone inserts (or raises) a tombstone and LRU-evicts if over cap.
func (r *Roster) addTombstone(id identity.NodeID, inc uint64, now time.Time) {
	r.tombSeq++
	r.tombstones[id] = tombstone{inc: inc, reapedAt: now, seq: r.tombSeq}
	if r.params.TombstoneCap > 0 && len(r.tombstones) > r.params.TombstoneCap {
		var oldestID identity.NodeID
		var oldestSeq = ^uint64(0)
		for tid, t := range r.tombstones {
			if t.seq < oldestSeq {
				oldestSeq, oldestID = t.seq, tid
			}
		}
		delete(r.tombstones, oldestID)
	}
}

// Row is a point-in-time roster row for the status view.
type Row struct {
	ID          identity.NodeID
	IsSelf      bool
	State       MemberState
	Incarnation uint64
	Endpoint    netip.AddrPort
	StateChange time.Time
}

// Rows returns the full roster (including self) for rendering, in no particular
// order; the caller sorts.
func (r *Roster) Rows() []Row {
	out := make([]Row, 0, len(r.members)+1)
	out = append(out, Row{ID: r.self, IsSelf: true, State: StateAlive, Incarnation: r.selfInc, Endpoint: r.selfEndpoint})
	for _, m := range r.members {
		out = append(out, Row{ID: m.ID, State: m.State, Incarnation: m.Incarnation, Endpoint: m.Endpoint, StateChange: m.StateChange})
	}
	return out
}

// GossipRows returns up to max priority-ordered updates describing the current
// roster (self first, then dead/left, then suspect, then alive), used to seed a
// join-sync burst on a completed handshake.
func (r *Roster) GossipRows(max int) []Update {
	all := make([]Update, 0, len(r.members)+1)
	all = append(all, r.SelfAlive())
	for _, m := range r.members {
		all = append(all, Update{NodeID: m.ID, Incarnation: m.Incarnation, Epoch: m.Epoch, State: m.State, Endpoint: m.Endpoint})
	}
	// Priority: higher gossipPriority first; self (Alive) sorts last among ties
	// but is always included because it is the refutation seed.
	sortByPriority(all)
	if max > 0 && len(all) > max {
		all = all[:max]
	}
	return all
}

// State returns a member's current state and whether it is known (for tests and
// the dial-hint gate).
func (r *Roster) State(id identity.NodeID) (MemberState, bool) {
	if id == r.self {
		return StateAlive, true
	}
	m := r.members[id]
	if m == nil {
		return 0, false
	}
	return m.State, true
}

// MemberCount returns the number of non-self members currently stored.
func (r *Roster) MemberCount() int { return len(r.members) }

// TombstoneCount returns the number of tombstones (bounded-memory assertions).
func (r *Roster) TombstoneCount() int { return len(r.tombstones) }

func ptr(u Update) *Update { return &u }
