package swim

import (
	"sort"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
)

// gossipPriority orders updates for dissemination: failure news and
// refutations must outrun routine chatter. Dead/Left are most urgent, then
// Suspect, then Alive.
func gossipPriority(s MemberState) int {
	switch s {
	case StateDead, StateLeft:
		return 2
	case StateSuspect:
		return 1
	default: // Alive
		return 0
	}
}

// sortByPriority orders updates highest-priority first (stable so equal-priority
// order is deterministic).
func sortByPriority(us []Update) {
	sort.SliceStable(us, func(i, j int) bool {
		return gossipPriority(us[i].State) > gossipPriority(us[j].State)
	})
}

// gossipEntry is one pending update with its remaining retransmit budget.
type gossipEntry struct {
	u         Update
	sendsLeft int
	// lastSent sequences transmits so Pick can prefer least-recently-sent
	// updates, spreading dissemination fairly.
	lastSent uint64
}

// Buffer is the bounded, infection-style gossip buffer. It is keyed by node ID
// so a newer update about a node replaces an older one (bounding memory to
// O(known nodes + recent churn)), and each entry is retransmitted a
// retransmit-count number of times then retired.
//
// Decrement is on actual transmit: Pick decrements sendsLeft as it seals an
// update into a frame, which is correct precisely because the node loop Seals
// frames directly and synchronously (no drop-on-full channel that could leak
// send credit).
type Buffer struct {
	items map[identity.NodeID]*gossipEntry
	seq   uint64
	cap   int
}

// NewBuffer returns a buffer bounded at cap entries (<=0 means unbounded, used
// only in unit tests).
func NewBuffer(capacity int) *Buffer {
	return &Buffer{items: make(map[identity.NodeID]*gossipEntry), cap: capacity}
}

// Add enqueues (or replaces) an update about a node with a fresh send budget.
// A replacement always wins its slot: the newest fact about a node is the one
// worth spreading, and older facts about it are strictly superseded by the
// lattice anyway. On overflow the lowest-priority, most-sent entry is dropped.
func (b *Buffer) Add(u Update, sends int) {
	if sends < 1 {
		sends = 1
	}
	if u.NodeID.IsZero() {
		return
	}
	b.items[u.NodeID] = &gossipEntry{u: u, sendsLeft: sends, lastSent: 0}
	b.evictIfNeeded()
}

func (b *Buffer) evictIfNeeded() {
	if b.cap <= 0 || len(b.items) <= b.cap {
		return
	}
	// Drop the least-worth-spreading entry: lowest priority, then most sends
	// already spent (largest lastSent), then arbitrary.
	var victimID identity.NodeID
	var have bool
	var vPrio int
	var vLastSent uint64
	for id, e := range b.items {
		p := gossipPriority(e.u.State)
		if !have || p < vPrio || (p == vPrio && e.lastSent > vLastSent) {
			victimID, vPrio, vLastSent, have = id, p, e.lastSent, true
		}
	}
	if have {
		delete(b.items, victimID)
	}
}

// Pick returns up to max updates to piggyback on an outgoing frame, highest
// priority first and least-recently-sent within a priority. It decrements each
// returned update's budget (decrement-on-transmit) and retires those that reach
// zero.
func (b *Buffer) Pick(max int) []Update {
	if max <= 0 || len(b.items) == 0 {
		return nil
	}
	entries := make([]*gossipEntry, 0, len(b.items))
	for _, e := range b.items {
		entries = append(entries, e)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		pi, pj := gossipPriority(entries[i].u.State), gossipPriority(entries[j].u.State)
		if pi != pj {
			return pi > pj
		}
		if entries[i].lastSent != entries[j].lastSent {
			return entries[i].lastSent < entries[j].lastSent
		}
		// Final tie-break on node ID for determinism.
		return less32(entries[i].u.NodeID, entries[j].u.NodeID)
	})
	if len(entries) > max {
		entries = entries[:max]
	}
	out := make([]Update, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.u)
		e.sendsLeft--
		b.seq++
		e.lastSent = b.seq
		if e.sendsLeft <= 0 {
			delete(b.items, e.u.NodeID)
		}
	}
	return out
}

// Len returns the number of pending entries (bounded-memory assertions).
func (b *Buffer) Len() int { return len(b.items) }

// Reset empties the buffer. It exists for the deterministic sim harness, which
// normalizes every node's gossip state to a known-empty baseline before
// measuring pure-infection convergence of a single injected fact (otherwise the
// nondeterministic real-time connect order leaves differing residual gossip).
func (b *Buffer) Reset() {
	b.items = make(map[identity.NodeID]*gossipEntry)
	b.seq = 0
}

func less32(a, b identity.NodeID) bool {
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
