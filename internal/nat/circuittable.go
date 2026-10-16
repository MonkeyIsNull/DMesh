package nat

import (
	"sort"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
)

// CircuitID identifies a relay circuit. On the relay it is the sole routing key
// between the two bound endpoints; authorization is the endpoint binding (see
// Other), never the id value, so the id may be unpredictable in production and
// deterministic in test without weakening security.
type CircuitID uint64

// OpenResult is the relay's verdict on a circuit-open request.
type OpenResult uint8

const (
	// OpenOK: a circuit was created (or an idempotent repeat matched an existing
	// one).
	OpenOK OpenResult = iota
	// OpenCapGlobal: the global circuit cap is reached.
	OpenCapGlobal
	// OpenCapRequester: the per-requester circuit cap is reached.
	OpenCapRequester
	// OpenRateLimited: the per-requester open-rate bucket is empty.
	OpenRateLimited
	// OpenCollision: the supplied id is already live.
	OpenCollision
)

// tokenBucket is a pure, now-driven token bucket with lazy refill (no timer
// goroutine). A zero-value bucket refills to burst on first use.
type tokenBucket struct {
	tokens float64
	last   time.Time
	rate   float64 // tokens per second
	burst  float64 // bucket capacity
}

func newBucket(rate, burst float64) *tokenBucket {
	return &tokenBucket{tokens: burst, rate: rate, burst: burst}
}

func (b *tokenBucket) refill(now time.Time) {
	if b.last.IsZero() {
		b.last = now
		if b.tokens == 0 {
			b.tokens = b.burst
		}
		return
	}
	if now.After(b.last) {
		b.tokens += now.Sub(b.last).Seconds() * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
}

// allow consumes n tokens if available, driven by now. A non-positive rate means
// "unlimited" (always allow).
func (b *tokenBucket) allow(n float64, now time.Time) bool {
	if b.rate <= 0 {
		return true
	}
	b.refill(now)
	if b.tokens >= n {
		b.tokens -= n
		return true
	}
	return false
}

// Circuit is one relayed path between endpoints A (the opener) and B (the
// target).
type Circuit struct {
	ID        CircuitID
	A, B      identity.NodeID
	createdAt time.Time
	lastData  time.Time
	bucket    tokenBucket
	// hsGrace is the remaining one-time handshake-grace budget (bytes). It is
	// drawn down only by well-formed handshake frames and never refills, so the
	// exemption is bounded to the inner Noise handshake and cannot be abused as a
	// sustained bypass of the byte buckets.
	hsGrace float64
}

type dedupKey struct {
	req   identity.NodeID
	nonce uint32
}

// CircuitTable is the relay's loop-owned circuit registry with caps and
// now-driven rate limits. It holds no inner A<->B keys: it is a dumb pipe.
type CircuitTable struct {
	p        Params
	circuits map[CircuitID]*Circuit
	perReq   map[identity.NodeID]int
	openRate map[identity.NodeID]*tokenBucket
	reqBytes map[identity.NodeID]*tokenBucket
	global   tokenBucket
	dedup    map[dedupKey]CircuitID
	dedupAt  map[dedupKey]time.Time
}

// NewCircuitTable builds an empty table under p (defaults filled).
func NewCircuitTable(p Params) *CircuitTable {
	p = p.WithDefaults()
	return &CircuitTable{
		p:        p,
		circuits: make(map[CircuitID]*Circuit),
		perReq:   make(map[identity.NodeID]int),
		openRate: make(map[identity.NodeID]*tokenBucket),
		reqBytes: make(map[identity.NodeID]*tokenBucket),
		global:   tokenBucket{tokens: bytesBurst(p.GlobalBytesPerSec), last: time.Time{}, rate: p.GlobalBytesPerSec, burst: bytesBurst(p.GlobalBytesPerSec)},
		dedup:    make(map[dedupKey]CircuitID),
		dedupAt:  make(map[dedupKey]time.Time),
	}
}

// bytesBurst gives a byte bucket one second of burst capacity.
func bytesBurst(ratePerSec float64) float64 {
	if ratePerSec <= 0 {
		return 0
	}
	return ratePerSec
}

// Len returns the number of live circuits.
func (t *CircuitTable) Len() int { return len(t.circuits) }

// Open registers a new circuit from requester to target, keyed by the
// caller-supplied id (drawn from the node's injectable RNG). It is idempotent: a
// repeat (requester, nonce) within DedupWindow returns the SAME existing circuit
// id. It enforces, in order, the dedup match, the global cap, the per-requester
// cap, the per-requester open-rate bucket, and id-collision rejection.
func (t *CircuitTable) Open(requester, target identity.NodeID, nonce uint32, id CircuitID, now time.Time) (CircuitID, OpenResult) {
	t.sweepDedup(now)
	key := dedupKey{req: requester, nonce: nonce}
	if existing, ok := t.dedup[key]; ok {
		if _, live := t.circuits[existing]; live {
			return existing, OpenOK
		}
		delete(t.dedup, key)
		delete(t.dedupAt, key)
	}
	if len(t.circuits) >= t.p.MaxCircuitsGlobal {
		return 0, OpenCapGlobal
	}
	if t.perReq[requester] >= t.p.MaxCircuitsPerRequester {
		return 0, OpenCapRequester
	}
	ob := t.openRate[requester]
	if ob == nil {
		ob = newBucket(t.p.OpenRatePerRequester, burstFor(t.p.OpenRatePerRequester))
		t.openRate[requester] = ob
	}
	if !ob.allow(1, now) {
		return 0, OpenRateLimited
	}
	if _, exists := t.circuits[id]; exists {
		return 0, OpenCollision
	}
	t.circuits[id] = &Circuit{
		ID:        id,
		A:         requester,
		B:         target,
		createdAt: now,
		lastData:  now,
		bucket:    tokenBucket{tokens: bytesBurst(t.p.PerCircuitBytesPerSec), rate: t.p.PerCircuitBytesPerSec, burst: bytesBurst(t.p.PerCircuitBytesPerSec)},
		hsGrace:   float64(t.p.HandshakeGraceBytes),
	}
	t.perReq[requester]++
	t.dedup[key] = id
	t.dedupAt[key] = now
	return id, OpenOK
}

func burstFor(ratePerSec float64) float64 {
	if ratePerSec <= 0 {
		return 0
	}
	if ratePerSec < 1 {
		return 1
	}
	return ratePerSec
}

func (t *CircuitTable) sweepDedup(now time.Time) {
	for k, at := range t.dedupAt {
		if now.Sub(at) >= t.p.DedupWindow {
			delete(t.dedupAt, k)
			delete(t.dedup, k)
		}
	}
}

// Other returns the far endpoint of circuit id as seen from `from`, and ok=true,
// ONLY if `from` is exactly one of the circuit's two registered endpoints. This
// is the authorization check that makes the relay a dumb pipe between two bound
// members: a third credentialed member whose frames carry a live circuit id it
// is not party to gets ok=false, so nothing is forwarded.
func (t *CircuitTable) Other(id CircuitID, from identity.NodeID) (identity.NodeID, bool) {
	c := t.circuits[id]
	if c == nil {
		return identity.NodeID{}, false
	}
	switch from {
	case c.A:
		return c.B, true
	case c.B:
		return c.A, true
	default:
		return identity.NodeID{}, false
	}
}

// Exists reports whether a circuit id is live.
func (t *CircuitTable) Exists(id CircuitID) bool {
	_, ok := t.circuits[id]
	return ok
}

// ChargeGlobal debits the global egress bucket, returning false (drop) when the
// relay's global ceiling is exceeded. The node calls this before Charge so
// circuits are shed first under global pressure.
func (t *CircuitTable) ChargeGlobal(nbytes int, now time.Time) bool {
	return t.global.allow(float64(nbytes), now)
}

// Charge debits the per-requester aggregate and per-circuit data buckets for a
// data frame on circuit id, and records data activity for idle reaping. It
// returns false (drop) when either bucket is exhausted. Control frames must NOT
// be charged (they are exempt so a data-plane limit can never starve a handshake
// or false-kill SWIM liveness).
func (t *CircuitTable) Charge(id CircuitID, nbytes int, now time.Time) bool {
	c := t.circuits[id]
	if c == nil {
		return false
	}
	c.lastData = now
	rb := t.reqBytes[c.A]
	if rb == nil {
		rb = &tokenBucket{tokens: bytesBurst(t.p.PerRequesterBytesPerSec), rate: t.p.PerRequesterBytesPerSec, burst: bytesBurst(t.p.PerRequesterBytesPerSec)}
		t.reqBytes[c.A] = rb
	}
	if !rb.allow(float64(nbytes), now) {
		return false
	}
	return c.bucket.allow(float64(nbytes), now)
}

// ConsumeHandshakeGrace draws nbytes from circuit id's one-time handshake-grace
// budget. It returns true (the frame is exempt from the byte buckets) only if
// the whole frame fits the remaining grace, consuming it; otherwise it returns
// false and consumes nothing, so the caller charges the frame against the byte
// buckets like data. The grace never refills, so only the bounded inner
// handshake is ever exempt - a sustained stream of handshake-typed frames spends
// the grace once and is charged thereafter. Callers pass only well-formed
// handshake frames here; data and malformed frames are charged directly.
func (t *CircuitTable) ConsumeHandshakeGrace(id CircuitID, nbytes int) bool {
	c := t.circuits[id]
	if c == nil {
		return false
	}
	if c.hsGrace >= float64(nbytes) {
		c.hsGrace -= float64(nbytes)
		return true
	}
	return false
}

// Touch records control-frame activity on a circuit (exempt from byte buckets)
// so an active-but-control-only circuit is not reaped as idle.
func (t *CircuitTable) Touch(id CircuitID, now time.Time) {
	if c := t.circuits[id]; c != nil {
		c.lastData = now
	}
}

// Close removes a circuit and frees its per-requester slot.
func (t *CircuitTable) Close(id CircuitID) {
	c := t.circuits[id]
	if c == nil {
		return
	}
	if n := t.perReq[c.A]; n > 0 {
		t.perReq[c.A] = n - 1
		if t.perReq[c.A] == 0 {
			delete(t.perReq, c.A)
		}
	}
	delete(t.circuits, id)
}

// ReapIdle closes every circuit idle longer than CircuitIdleTimeout and returns
// their ids sorted ascending, so the loop's circClose emissions are
// deterministic (no map-iteration order dependence).
func (t *CircuitTable) ReapIdle(now time.Time) []CircuitID {
	var ids []CircuitID
	for id, c := range t.circuits {
		if now.Sub(c.lastData) >= t.p.CircuitIdleTimeout {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		t.Close(id)
	}
	return ids
}

// Endpoints returns the two bound endpoints of a circuit (for tests/status).
func (t *CircuitTable) Endpoints(id CircuitID) (a, b identity.NodeID, ok bool) {
	c := t.circuits[id]
	if c == nil {
		return identity.NodeID{}, identity.NodeID{}, false
	}
	return c.A, c.B, true
}

// ReapedCircuit is one idle circuit removed by ReapIdleWithEndpoints, carrying
// the endpoints captured BEFORE the circuit was closed so the relay can still
// notify both sides.
type ReapedCircuit struct {
	ID   CircuitID
	A, B identity.NodeID
}

// ReapIdleWithEndpoints is ReapIdle but returns each reaped circuit's endpoints
// (captured before close), sorted ascending by id for deterministic emission.
func (t *CircuitTable) ReapIdleWithEndpoints(now time.Time) []ReapedCircuit {
	var out []ReapedCircuit
	for id, c := range t.circuits {
		if now.Sub(c.lastData) >= t.p.CircuitIdleTimeout {
			out = append(out, ReapedCircuit{ID: id, A: c.A, B: c.B})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	for _, rc := range out {
		t.Close(rc.ID)
	}
	return out
}
