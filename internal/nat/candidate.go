// Package nat is the pure, side-effect-free NAT-traversal core for DMesh v0.4.
// Mirroring internal/swim and internal/session, it contains no goroutines, no
// sockets, and no clock of its own: every method takes the current time plus
// inbound data and returns decisions. All concurrency and I/O live in package
// node, whose single event-loop goroutine owns the circuit table and candidate
// store and drives them.
//
// The package deliberately imports only identity, crypto/ed25519, net/netip and
// time. It imports neither swim nor node, so the SWIM failure detector stays
// entirely free of any NAT dependency: candidates ride as a node-owned, signed,
// independently-versioned extension that node appends and parses in its own
// gossip wrapper (see package node), never inside a swim envelope.
package nat

import (
	"crypto/ed25519"
	"encoding/binary"
	"net/netip"
	"sort"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
)

// CandidateType classifies how a transport address was learned.
type CandidateType uint8

const (
	// CandHost is a locally-observed interface address.
	CandHost CandidateType = 1
	// CandReflexive is a NAT-translated public address observed by a peer
	// (serverless STUN). It is only ever advertised after corroboration.
	CandReflexive CandidateType = 2
	// CandRelay is a relay-reachability hint (Phase 2 seam; not dialed in v0.4).
	CandRelay CandidateType = 3
)

func validCandType(t CandidateType) bool {
	return t == CandHost || t == CandReflexive || t == CandRelay
}

// Candidate is one advertised transport address of a node.
type Candidate struct {
	Addr netip.AddrPort
	Type CandidateType
}

// Caps is a node's advertised NAT-traversal capability bitset.
type Caps uint8

const (
	// CapRelay advertises that the node will act as a relay for credentialed
	// members (see package node, --relay).
	CapRelay Caps = 1 << 0
	// CapNat advertises that the node participates in reflexive discovery.
	CapNat Caps = 1 << 1
)

// CandSet is a node's signed, independently-versioned candidate record.
//
// Gen is an independent monotonic generation (candGen), NOT the SWIM
// (incarnation,state) lattice: it never touches the failure-detector incarnation
// space. Sig is an Ed25519 signature by the subject node over the canonical
// encoding of (subjectNodeID || Gen || Caps || DedupSort(Cands)). Because a
// NodeID IS the Ed25519 public key (see internal/identity), a set verifies
// against its subject with no key distribution, so a candidate is authenticated
// to its subject and a relayer cannot forge another node's set.
type CandSet struct {
	Gen   uint64
	Caps  Caps
	Cands []Candidate
	Sig   []byte
}

// candPriority ranks a candidate for both Primary selection and bounded-set
// eviction: lower is preferred/kept. The order is host-public > reflexive >
// host-private > relay.
func candPriority(c Candidate) int {
	switch c.Type {
	case CandHost:
		a := c.Addr.Addr()
		if a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLoopback() {
			return 2 // host-private
		}
		return 0 // host-public
	case CandReflexive:
		return 1
	case CandRelay:
		return 3
	default:
		return 4
	}
}

// addrLess is a total order on AddrPort by 16-byte address then port.
func addrLess(a, b netip.AddrPort) bool {
	a16, b16 := a.Addr().As16(), b.Addr().As16()
	for i := 0; i < 16; i++ {
		if a16[i] != b16[i] {
			return a16[i] < b16[i]
		}
	}
	return a.Port() < b.Port()
}

// DedupSort returns the candidates in a stable total order (priority rank, then
// type, then address bytes) with exact (Type, Addr) duplicates removed. The
// order is both the canonical signing order and the eviction priority, so a
// bounded candidate set keeps the N highest-priority members and never
// oscillates: it is convergent.
func DedupSort(in []Candidate) []Candidate {
	out := make([]Candidate, 0, len(in))
	for _, c := range in {
		if !validCandType(c.Type) || !c.Addr.IsValid() {
			continue
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		pi, pj := candPriority(out[i]), candPriority(out[j])
		if pi != pj {
			return pi < pj
		}
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return addrLess(out[i].Addr, out[j].Addr)
	})
	// Remove exact (Type, Addr) duplicates; the stable sort keeps them adjacent.
	w := 0
	for i := 0; i < len(out); i++ {
		if i > 0 && out[i].Type == out[i-1].Type && out[i].Addr == out[i-1].Addr {
			continue
		}
		out[w] = out[i]
		w++
	}
	return out[:w]
}

// BoundSet trims a candidate set to at most max members by eviction priority.
func BoundSet(in []Candidate, max int) []Candidate {
	s := DedupSort(in)
	if max > 0 && len(s) > max {
		s = s[:max]
	}
	return s
}

// appendEndpoint serializes an AddrPort as family(1)/addr/port. It is a private
// copy of the swim codec's encoding, duplicated deliberately so package swim
// never gains a dependency on package nat (see the package doc).
func appendEndpoint(buf []byte, ep netip.AddrPort) []byte {
	if !ep.IsValid() {
		return append(buf, famNone)
	}
	addr := ep.Addr()
	if addr.Is4() {
		b4 := addr.As4()
		buf = append(buf, fam4)
		buf = append(buf, b4[:]...)
	} else {
		b16 := addr.As16()
		buf = append(buf, fam6)
		buf = append(buf, b16[:]...)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], ep.Port())
	return append(buf, port[:]...)
}

// canonical builds the exact bytes signed and verified for a candidate set:
// subjectNodeID || Gen(8) || Caps(1) || for each DedupSort'd candidate
// { type(1), endpoint-enc }. Reordering on the wire cannot change it because
// the candidates are always re-sorted here.
func canonical(subject identity.NodeID, gen uint64, caps Caps, cands []Candidate) []byte {
	sorted := DedupSort(cands)
	buf := make([]byte, 0, 32+8+1+len(sorted)*21)
	buf = append(buf, subject[:]...)
	var g [8]byte
	binary.BigEndian.PutUint64(g[:], gen)
	buf = append(buf, g[:]...)
	buf = append(buf, byte(caps))
	for _, c := range sorted {
		buf = append(buf, byte(c.Type))
		buf = appendEndpoint(buf, c.Addr)
	}
	return buf
}

// SignSelf builds a CandSet signed by id over the canonical encoding. The stored
// Cands are the dedup-sorted set, so what is signed and what is carried match.
func SignSelf(id *identity.Identity, gen uint64, caps Caps, cands []Candidate) CandSet {
	sorted := DedupSort(cands)
	sig := ed25519.Sign(id.Signing, canonical(id.NodeID(), gen, caps, sorted))
	return CandSet{Gen: gen, Caps: caps, Cands: sorted, Sig: sig}
}

// Verify reports whether cs is a valid set authored by subject. It recomputes
// the canonical encoding (re-sorting the candidates) and checks the Ed25519
// signature against subject's public key (the NodeID itself).
func Verify(subject identity.NodeID, cs CandSet) bool {
	if len(cs.Sig) != ed25519.SignatureSize {
		return false
	}
	for _, c := range cs.Cands {
		if !validCandType(c.Type) || !c.Addr.IsValid() {
			return false
		}
	}
	return ed25519.Verify(subject.Ed25519(), canonical(subject, cs.Gen, cs.Caps, cs.Cands), cs.Sig)
}

// Primary returns the single best dialable address (host-public > reflexive >
// host-private) for the legacy Endpoint dial hint, or the zero AddrPort if the
// set has no dialable candidate. Relay candidates are never returned as a direct
// dial hint.
func Primary(cands []Candidate) netip.AddrPort {
	sorted := DedupSort(cands)
	for _, c := range sorted {
		if c.Type == CandRelay {
			continue
		}
		return c.Addr
	}
	return netip.AddrPort{}
}

// Equal reports whether two candidate sets carry the same dedup-sorted
// candidates and caps (ignoring Gen and Sig), used to decide whether a self-set
// changed materially enough to bump candGen.
func Equal(a, b CandSet) bool {
	if a.Caps != b.Caps {
		return false
	}
	as, bs := DedupSort(a.Cands), DedupSort(b.Cands)
	if len(as) != len(bs) {
		return false
	}
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}
