package nat

import "time"

// Params holds every tunable of the NAT/relay layer. DefaultParams returns the
// production values; tests tighten the caps, rates, and timers so the injectable
// clock drives everything deterministically, exactly like swim.Params and
// session.Params.
type Params struct {
	// --- circuit caps (relay side) ---

	// MaxCircuitsGlobal bounds total live circuits a relay carries.
	MaxCircuitsGlobal int
	// MaxCircuitsPerRequester bounds live circuits one opener may hold on a relay.
	MaxCircuitsPerRequester int
	// MaxInboundCircuitsPerNode bounds circuits a target node accepts in total.
	MaxInboundCircuitsPerNode int
	// MaxInboundCircuitsPerRelay bounds circuits a target accepts via one relay.
	MaxInboundCircuitsPerRelay int

	// --- rate limits ---

	// PerCircuitBytesPerSec caps data-plane bytes per circuit (control-exempt).
	PerCircuitBytesPerSec float64
	// PerRequesterBytesPerSec caps aggregate data bytes across one opener's
	// circuits.
	PerRequesterBytesPerSec float64
	// GlobalBytesPerSec is the relay's global data-plane egress ceiling; circuits
	// are shed first under global pressure.
	GlobalBytesPerSec float64
	// HandshakeGraceBytes is the one-time per-circuit byte budget exempt from the
	// byte buckets, sized for the inner Noise handshake (with retransmits). Only
	// well-formed handshake frames draw on it; once it is spent, handshake frames
	// are charged exactly like data, so a flood of handshake-typed frames cannot
	// bypass the per-circuit/per-requester/global ceilings. It must comfortably
	// exceed the real inner-handshake transcript so a legitimate handshake is
	// never starved by a rate limit.
	HandshakeGraceBytes int
	// OpenRatePerRequester caps circuit-open attempts per opener per second.
	OpenRatePerRequester float64
	// ReflexRespRatePerSource caps reflex responses emitted to one source.
	ReflexRespRatePerSource float64

	// --- timers / corroboration / dial caps ---

	// CircuitIdleTimeout is how long a circuit may carry no data before it is
	// reaped at both the relay and the endpoints.
	CircuitIdleTimeout time.Duration
	// PendingOpenTimeout is how long an opener keeps an unacked circuit-open
	// (pendingOpens) entry before sweeping it. A lost circOpen or circOpenAck
	// would otherwise leak the entry forever and - because reopen/dial dedup
	// against it by target - permanently wedge relay fallback to that target. The
	// sweep lets the next session tick re-issue the open. It must exceed a
	// plausible open round-trip so a legitimate in-flight ack is not raced by a
	// duplicate open.
	PendingOpenTimeout time.Duration
	// DedupWindow is how long an (opener, nonce) open is deduplicated to the same
	// circuit id.
	DedupWindow time.Duration
	// ReflexInterval is the reflex-probe cadence.
	ReflexInterval time.Duration
	// ReflexMaxPeers caps how many peers are probed per reflex round.
	ReflexMaxPeers int
	// MinReflexObservers is how many independent observers must report the same
	// ip:port before a reflexive candidate is promoted (anti-reflection).
	MinReflexObservers int
	// MaxCandidatesPerMember bounds candidates kept/advertised per member.
	MaxCandidatesPerMember int
	// MaxCandidatesPerFrame bounds candidates serialized per gossip frame.
	MaxCandidatesPerFrame int
	// MaxOutstandingDialsPerPeer / Global cap candidate dial attempts.
	MaxOutstandingDialsPerPeer int
	// MaxOutstandingDialsGlobal caps candidate dial attempts across all peers.
	MaxOutstandingDialsGlobal int
}

// DefaultParams returns the production NAT parameters.
func DefaultParams() Params {
	return Params{
		MaxCircuitsGlobal:          256,
		MaxCircuitsPerRequester:    8,
		MaxInboundCircuitsPerNode:  16,
		MaxInboundCircuitsPerRelay: 8,
		PerCircuitBytesPerSec:      1 << 20, // 1 MiB/s
		PerRequesterBytesPerSec:    2 << 20, // 2 MiB/s
		GlobalBytesPerSec:          8 << 20, // 8 MiB/s shed-first ceiling
		HandshakeGraceBytes:        8192,    // ~20x the inner Noise XX transcript
		OpenRatePerRequester:       4,
		ReflexRespRatePerSource:    2,
		CircuitIdleTimeout:         30 * time.Second,
		PendingOpenTimeout:         2 * time.Second,
		DedupWindow:                5 * time.Second,
		ReflexInterval:             20 * time.Second,
		ReflexMaxPeers:             2,
		MinReflexObservers:         2,
		MaxCandidatesPerMember:     4,
		MaxCandidatesPerFrame:      6,
		MaxOutstandingDialsPerPeer: 2,
		MaxOutstandingDialsGlobal:  16,
	}
}

// WithDefaults fills every zero-valued field from DefaultParams, so a caller may
// override a single tunable and still get sane values for the rest (mirrors
// session.Params.WithDefaults).
func (p Params) WithDefaults() Params {
	d := DefaultParams()
	if p.MaxCircuitsGlobal == 0 {
		p.MaxCircuitsGlobal = d.MaxCircuitsGlobal
	}
	if p.MaxCircuitsPerRequester == 0 {
		p.MaxCircuitsPerRequester = d.MaxCircuitsPerRequester
	}
	if p.MaxInboundCircuitsPerNode == 0 {
		p.MaxInboundCircuitsPerNode = d.MaxInboundCircuitsPerNode
	}
	if p.MaxInboundCircuitsPerRelay == 0 {
		p.MaxInboundCircuitsPerRelay = d.MaxInboundCircuitsPerRelay
	}
	if p.PerCircuitBytesPerSec == 0 {
		p.PerCircuitBytesPerSec = d.PerCircuitBytesPerSec
	}
	if p.PerRequesterBytesPerSec == 0 {
		p.PerRequesterBytesPerSec = d.PerRequesterBytesPerSec
	}
	if p.GlobalBytesPerSec == 0 {
		p.GlobalBytesPerSec = d.GlobalBytesPerSec
	}
	if p.HandshakeGraceBytes == 0 {
		p.HandshakeGraceBytes = d.HandshakeGraceBytes
	}
	if p.OpenRatePerRequester == 0 {
		p.OpenRatePerRequester = d.OpenRatePerRequester
	}
	if p.ReflexRespRatePerSource == 0 {
		p.ReflexRespRatePerSource = d.ReflexRespRatePerSource
	}
	if p.CircuitIdleTimeout == 0 {
		p.CircuitIdleTimeout = d.CircuitIdleTimeout
	}
	if p.PendingOpenTimeout == 0 {
		p.PendingOpenTimeout = d.PendingOpenTimeout
	}
	if p.DedupWindow == 0 {
		p.DedupWindow = d.DedupWindow
	}
	if p.ReflexInterval == 0 {
		p.ReflexInterval = d.ReflexInterval
	}
	if p.ReflexMaxPeers == 0 {
		p.ReflexMaxPeers = d.ReflexMaxPeers
	}
	if p.MinReflexObservers == 0 {
		p.MinReflexObservers = d.MinReflexObservers
	}
	if p.MaxCandidatesPerMember == 0 {
		p.MaxCandidatesPerMember = d.MaxCandidatesPerMember
	}
	if p.MaxCandidatesPerFrame == 0 {
		p.MaxCandidatesPerFrame = d.MaxCandidatesPerFrame
	}
	if p.MaxOutstandingDialsPerPeer == 0 {
		p.MaxOutstandingDialsPerPeer = d.MaxOutstandingDialsPerPeer
	}
	if p.MaxOutstandingDialsGlobal == 0 {
		p.MaxOutstandingDialsGlobal = d.MaxOutstandingDialsGlobal
	}
	return p
}
