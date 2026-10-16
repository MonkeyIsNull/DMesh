package nat

import (
	"encoding/binary"
	"net/netip"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
)

// Wire formats for the NAT/relay sub-protocols. Every decode is bounds-checked
// against the remaining buffer BEFORE any allocation (the same reader discipline
// as internal/swim/codec.go) and NEVER panics; it returns ok=false on
// truncation, over-cap, an unknown version, or an unknown sub-type.
//
// Forward-compat contract (enforced by construction): an unknown version OR an
// unknown sub decodes to ok=false, and every node handler that gets ok=false
// silently drops the body - it never errors the session, bumps liveness, or
// closes a circuit. This keeps v0.5 free to add sub-types that v0.4 ignores.
const (
	natVersion   = 1
	relayVersion = 1

	// Reflex sub-protocol (carried under node app-type msgNat).
	ReflexReq  = 1
	ReflexResp = 2

	// Circuit-control sub-protocol (carried under node app-type msgRelay).
	CircOpen       = 1
	CircOpenAck    = 2
	CircOpenNotify = 3
	CircData       = 4
	CircClose      = 5

	// circOpenAck status codes.
	CircStatusOK          = 0
	CircStatusDenied      = 1
	CircStatusNoCap       = 2
	CircStatusRateLimited = 3

	// Signed-candidate gossip extension (appended by node after a swim payload).
	candExtMarker = 0xC1
	candExtVer    = 1

	famNone = 0
	fam4    = 4
	fam6    = 6

	nodeIDLen = 32
)

// --- reflex ----------------------------------------------------------------

// EncodeReflexReq builds a reflex request body (no payload beyond the header).
func EncodeReflexReq() []byte {
	return []byte{natVersion, ReflexReq}
}

// EncodeReflexResp builds a reflex response carrying the observed address.
func EncodeReflexResp(observed netip.AddrPort) []byte {
	buf := []byte{natVersion, ReflexResp}
	return appendEndpoint(buf, observed)
}

// ReflexMsg is a decoded reflex message.
type ReflexMsg struct {
	Sub      uint8
	Observed netip.AddrPort // valid only for ReflexResp
}

// DecodeReflex parses a reflex body. ok=false for unknown version/sub or
// truncation.
func DecodeReflex(b []byte) (ReflexMsg, bool) {
	r := reader{b: b}
	ver, ok := r.u8()
	if !ok || ver != natVersion {
		return ReflexMsg{}, false
	}
	sub, ok := r.u8()
	if !ok {
		return ReflexMsg{}, false
	}
	switch sub {
	case ReflexReq:
		return ReflexMsg{Sub: sub}, true
	case ReflexResp:
		ep, ok := r.endpoint()
		if !ok {
			return ReflexMsg{}, false
		}
		return ReflexMsg{Sub: sub, Observed: ep}, true
	default:
		return ReflexMsg{}, false
	}
}

// --- circuit control -------------------------------------------------------

// RelayMsg is a decoded circuit-control message. Only the fields relevant to Sub
// are populated.
type RelayMsg struct {
	Sub       uint8
	Target    identity.NodeID // CircOpen
	Source    identity.NodeID // CircOpenNotify
	ReqNonce  uint32          // CircOpen, CircOpenAck
	Status    uint8           // CircOpenAck
	CircuitID CircuitID       // CircOpenAck, CircOpenNotify, CircData, CircClose
	Code      uint8           // CircClose
	Payload   []byte          // CircData inner datagram (tail, not copied)
}

// EncodeCircOpen (opener -> relay).
func EncodeCircOpen(target identity.NodeID, reqNonce uint32) []byte {
	buf := []byte{relayVersion, CircOpen}
	buf = append(buf, target[:]...)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], reqNonce)
	return append(buf, n[:]...)
}

// EncodeCircOpenAck (relay -> opener).
func EncodeCircOpenAck(reqNonce uint32, status uint8, id CircuitID) []byte {
	buf := []byte{relayVersion, CircOpenAck}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], reqNonce)
	buf = append(buf, n[:]...)
	buf = append(buf, status)
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], uint64(id))
	return append(buf, c[:]...)
}

// EncodeCircOpenNotify (relay -> target).
func EncodeCircOpenNotify(source identity.NodeID, id CircuitID) []byte {
	buf := []byte{relayVersion, CircOpenNotify}
	buf = append(buf, source[:]...)
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], uint64(id))
	return append(buf, c[:]...)
}

// EncodeCircData (endpoint <-> relay). The inner opaque datagram is the tail.
func EncodeCircData(id CircuitID, inner []byte) []byte {
	buf := make([]byte, 0, 2+8+len(inner))
	buf = append(buf, relayVersion, CircData)
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], uint64(id))
	buf = append(buf, c[:]...)
	return append(buf, inner...)
}

// EncodeCircClose (any <-> relay).
func EncodeCircClose(id CircuitID, code uint8) []byte {
	buf := []byte{relayVersion, CircClose}
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], uint64(id))
	buf = append(buf, c[:]...)
	return append(buf, code)
}

// DecodeRelay parses a circuit-control body. ok=false for unknown version/sub or
// truncation. For CircData, Payload aliases the tail of b (the caller copies it
// before retaining).
func DecodeRelay(b []byte) (RelayMsg, bool) {
	r := reader{b: b}
	ver, ok := r.u8()
	if !ok || ver != relayVersion {
		return RelayMsg{}, false
	}
	sub, ok := r.u8()
	if !ok {
		return RelayMsg{}, false
	}
	m := RelayMsg{Sub: sub}
	switch sub {
	case CircOpen:
		if !r.bytes(m.Target[:]) {
			return RelayMsg{}, false
		}
		n, ok := r.u32()
		if !ok {
			return RelayMsg{}, false
		}
		m.ReqNonce = n
		return m, true
	case CircOpenAck:
		n, ok := r.u32()
		if !ok {
			return RelayMsg{}, false
		}
		m.ReqNonce = n
		st, ok := r.u8()
		if !ok {
			return RelayMsg{}, false
		}
		m.Status = st
		id, ok := r.u64()
		if !ok {
			return RelayMsg{}, false
		}
		m.CircuitID = CircuitID(id)
		return m, true
	case CircOpenNotify:
		if !r.bytes(m.Source[:]) {
			return RelayMsg{}, false
		}
		id, ok := r.u64()
		if !ok {
			return RelayMsg{}, false
		}
		m.CircuitID = CircuitID(id)
		return m, true
	case CircData:
		id, ok := r.u64()
		if !ok {
			return RelayMsg{}, false
		}
		m.CircuitID = CircuitID(id)
		m.Payload = r.tail()
		return m, true
	case CircClose:
		id, ok := r.u64()
		if !ok {
			return RelayMsg{}, false
		}
		m.CircuitID = CircuitID(id)
		code, ok := r.u8()
		if !ok {
			return RelayMsg{}, false
		}
		m.Code = code
		return m, true
	default:
		return RelayMsg{}, false
	}
}

// --- signed candidate extension --------------------------------------------

// CandMember pairs a subject node ID with its signed candidate set, as carried
// in one slot of the gossip extension.
type CandMember struct {
	Subject identity.NodeID
	Set     CandSet
}

// EncodeCandExt serializes zero or more signed candidate sets as a trailing
// gossip extension:
//
//	extMarker(1)=0xC1 extVer(1)=1 setCount(1)
//	per member: nodeID(32) gen(8) caps(1) sigLen(1) sig(sigLen)
//	            candCount(1) candCount*{ type(1) endpoint-enc }
//
// The caller appends it after a complete swim payload and must only include as
// many members as fit the frame's byte budget. maxCands bounds candidates per
// member on the wire.
func EncodeCandExt(members []CandMember, maxCands int) []byte {
	n := len(members)
	if n > 255 {
		n = 255
	}
	buf := []byte{candExtMarker, candExtVer, byte(n)}
	for i := 0; i < n; i++ {
		m := members[i]
		buf = append(buf, m.Subject[:]...)
		var g [8]byte
		binary.BigEndian.PutUint64(g[:], m.Set.Gen)
		buf = append(buf, g[:]...)
		buf = append(buf, byte(m.Set.Caps))
		sig := m.Set.Sig
		if len(sig) > 255 {
			sig = sig[:255]
		}
		buf = append(buf, byte(len(sig)))
		buf = append(buf, sig...)
		cands := m.Set.Cands
		if maxCands > 0 && len(cands) > maxCands {
			cands = cands[:maxCands]
		}
		if len(cands) > 255 {
			cands = cands[:255]
		}
		buf = append(buf, byte(len(cands)))
		for _, c := range cands {
			buf = append(buf, byte(c.Type))
			buf = appendEndpoint(buf, c.Addr)
		}
	}
	return buf
}

// EncodedCandMemberLen returns the exact wire length one member occupies in the
// extension, so the node can honor a running byte budget without trial encoding.
func EncodedCandMemberLen(m CandMember, maxCands int) int {
	cands := m.Set.Cands
	if maxCands > 0 && len(cands) > maxCands {
		cands = cands[:maxCands]
	}
	total := nodeIDLen + 8 + 1 + 1 + len(m.Set.Sig) + 1
	for _, c := range cands {
		total += 1 + endpointLen(c.Addr)
	}
	return total
}

func endpointLen(ep netip.AddrPort) int {
	if !ep.IsValid() {
		return 1
	}
	if ep.Addr().Is4() {
		return 1 + 4 + 2
	}
	return 1 + 16 + 2
}

// FindCandExt locates the candidate extension within a decoded gossip payload.
// The node calls swim.Decode on the leading bytes; this scans the full frame for
// the extension marker. It returns the extension's byte offset and true if
// present. Because the marker could in principle collide with swim payload
// bytes, the node only trusts an extension that parses cleanly AND whose member
// signatures verify; a false positive simply yields unverifiable junk that is
// dropped.
func FindCandExt(full []byte, swimLen int) (int, bool) {
	if swimLen < 0 || swimLen >= len(full) {
		return 0, false
	}
	if full[swimLen] == candExtMarker {
		return swimLen, true
	}
	return 0, false
}

// DecodeCandExt parses the extension at b. ok=false (silent drop) for unknown
// marker/version, truncation, or over-cap. Signature verification is the
// caller's responsibility (per subject).
func DecodeCandExt(b []byte) ([]CandMember, bool) {
	r := reader{b: b}
	marker, ok := r.u8()
	if !ok || marker != candExtMarker {
		return nil, false
	}
	ver, ok := r.u8()
	if !ok || ver != candExtVer {
		return nil, false
	}
	count, ok := r.u8()
	if !ok {
		return nil, false
	}
	members := make([]CandMember, 0, count)
	for i := 0; i < int(count); i++ {
		var m CandMember
		if !r.bytes(m.Subject[:]) {
			return nil, false
		}
		gen, ok := r.u64()
		if !ok {
			return nil, false
		}
		m.Set.Gen = gen
		caps, ok := r.u8()
		if !ok {
			return nil, false
		}
		m.Set.Caps = Caps(caps)
		sigLen, ok := r.u8()
		if !ok {
			return nil, false
		}
		sig := make([]byte, sigLen)
		if !r.bytes(sig) {
			return nil, false
		}
		m.Set.Sig = sig
		candCount, ok := r.u8()
		if !ok {
			return nil, false
		}
		if int(candCount) > 0 {
			m.Set.Cands = make([]Candidate, 0, candCount)
		}
		for j := 0; j < int(candCount); j++ {
			t, ok := r.u8()
			if !ok {
				return nil, false
			}
			ep, ok := r.endpoint()
			if !ok {
				return nil, false
			}
			m.Set.Cands = append(m.Set.Cands, Candidate{Addr: ep, Type: CandidateType(t)})
		}
		members = append(members, m)
	}
	return members, true
}

// --- bounds-checked reader (private copy of the swim reader discipline) -----

type reader struct {
	b   []byte
	off int
}

func (r *reader) u8() (uint8, bool) {
	if r.off+1 > len(r.b) {
		return 0, false
	}
	v := r.b[r.off]
	r.off++
	return v, true
}

func (r *reader) u32() (uint32, bool) {
	if r.off+4 > len(r.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.b[r.off : r.off+4])
	r.off += 4
	return v, true
}

func (r *reader) u64() (uint64, bool) {
	if r.off+8 > len(r.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint64(r.b[r.off : r.off+8])
	r.off += 8
	return v, true
}

func (r *reader) u16() (uint16, bool) {
	if r.off+2 > len(r.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint16(r.b[r.off : r.off+2])
	r.off += 2
	return v, true
}

func (r *reader) bytes(dst []byte) bool {
	if r.off+len(dst) > len(r.b) {
		return false
	}
	copy(dst, r.b[r.off:r.off+len(dst)])
	r.off += len(dst)
	return true
}

func (r *reader) tail() []byte {
	t := r.b[r.off:]
	r.off = len(r.b)
	return t
}

func (r *reader) endpoint() (netip.AddrPort, bool) {
	fam, ok := r.u8()
	if !ok {
		return netip.AddrPort{}, false
	}
	switch fam {
	case famNone:
		return netip.AddrPort{}, true
	case fam4:
		var a [4]byte
		if !r.bytes(a[:]) {
			return netip.AddrPort{}, false
		}
		p, ok := r.u16()
		if !ok {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(netip.AddrFrom4(a), p), true
	case fam6:
		var a [16]byte
		if !r.bytes(a[:]) {
			return netip.AddrPort{}, false
		}
		p, ok := r.u16()
		if !ok {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(netip.AddrFrom16(a), p), true
	default:
		return netip.AddrPort{}, false
	}
}
