package swim

import (
	"encoding/binary"
	"net/netip"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
)

// Wire format of a SWIM envelope, carried as the body of a transport data frame
// whose app type is msgSwim (0x10, defined in package node). Distinct from the
// v0.1 app messages.
//
//	version(1)=1
//	kind(1)       ping|ack|pingReq|pingReqAck|sync
//	seq(4)        correlates ping<->ack and pingReq<->pingReqAck
//	[ kind==pingReq || kind==pingReqAck ]
//	  targetID(32)
//	  targetEndpoint = endpoint-enc        (roster dial hint only)
//	updateCount(1)  <= MaxUpdatesPerFrame
//	updateCount * Update:
//	  state(1) incarnation(8) epoch(1) nodeID(32) endpoint-enc
//	endpoint-enc: family(1: 0|4|6) then
//	  family 0 -> (nothing: invalid/unknown endpoint)
//	  family 4 -> addr(4) port(2)
//	  family 6 -> addr(16) port(2)
//
// Every length is validated against the remaining buffer BEFORE any allocation,
// so a credentialed-but-malicious peer cannot trigger a large allocation or a
// panic with a truncated or inflated frame.
const (
	swimVersion = 1

	// MaxUpdatesPerFrame is a hard decode cap (independent of the softer
	// Params.MaxPiggyback send budget) above which a frame is rejected cheaply.
	MaxUpdatesPerFrame = 64

	famNone = 0
	fam4    = 4
	fam6    = 6
)

// Encode serializes an envelope. It never produces more than
// MaxUpdatesPerFrame updates (the caller's Pick budget is far smaller).
func Encode(env Envelope) []byte {
	buf := make([]byte, 0, 64)
	buf = append(buf, swimVersion, env.Kind)
	var seq [4]byte
	binary.BigEndian.PutUint32(seq[:], env.Seq)
	buf = append(buf, seq[:]...)

	if env.Kind == KindPingReq || env.Kind == KindPingReqAck {
		buf = append(buf, env.Target[:]...)
		buf = appendEndpoint(buf, env.TargetEndpoint)
	}

	n := len(env.Updates)
	if n > MaxUpdatesPerFrame {
		n = MaxUpdatesPerFrame
	}
	buf = append(buf, byte(n))
	for i := 0; i < n; i++ {
		u := env.Updates[i]
		buf = append(buf, byte(u.State))
		var inc [8]byte
		binary.BigEndian.PutUint64(inc[:], u.Incarnation)
		buf = append(buf, inc[:]...)
		buf = append(buf, u.Epoch)
		buf = append(buf, u.NodeID[:]...)
		buf = appendEndpoint(buf, u.Endpoint)
	}
	return buf
}

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

// Envelope is a decoded SWIM frame.
type Envelope struct {
	Kind           uint8
	Seq            uint32
	Target         identity.NodeID
	TargetEndpoint netip.AddrPort
	Updates        []Update
}

// SWIM frame kinds.
const (
	KindPing       uint8 = 1
	KindAck        uint8 = 2
	KindPingReq    uint8 = 3
	KindPingReqAck uint8 = 4
	KindSync       uint8 = 5
)

const (
	nodeIDLen   = 32
	updateFixed = 1 + 8 + 1 + nodeIDLen // state+inc+epoch+nodeID, before endpoint
)

// Decode parses an envelope body. It returns ok=false (never panics) for any
// malformed, truncated, over-cap, or unknown-version/kind input.
func Decode(b []byte) (Envelope, bool) {
	var env Envelope
	r := reader{b: b}
	ver, ok := r.u8()
	if !ok || ver != swimVersion {
		return env, false
	}
	kind, ok := r.u8()
	if !ok || !validKind(kind) {
		return env, false
	}
	env.Kind = kind
	seq, ok := r.u32()
	if !ok {
		return env, false
	}
	env.Seq = seq

	if kind == KindPingReq || kind == KindPingReqAck {
		var id identity.NodeID
		if !r.bytes(id[:]) {
			return env, false
		}
		env.Target = id
		ep, ok := r.endpoint()
		if !ok {
			return env, false
		}
		env.TargetEndpoint = ep
	}

	count, ok := r.u8()
	if !ok || int(count) > MaxUpdatesPerFrame {
		return env, false
	}
	if count > 0 {
		env.Updates = make([]Update, 0, count)
	}
	for i := 0; i < int(count); i++ {
		st, ok := r.u8()
		if !ok {
			return env, false
		}
		inc, ok := r.u64()
		if !ok {
			return env, false
		}
		ep8, ok := r.u8()
		if !ok {
			return env, false
		}
		var id identity.NodeID
		if !r.bytes(id[:]) {
			return env, false
		}
		endp, ok := r.endpoint()
		if !ok {
			return env, false
		}
		env.Updates = append(env.Updates, Update{
			NodeID:      id,
			Incarnation: inc,
			Epoch:       ep8,
			State:       MemberState(st),
			Endpoint:    endp,
		})
	}
	return env, true
}

func validKind(k uint8) bool {
	switch k {
	case KindPing, KindAck, KindPingReq, KindPingReqAck, KindSync:
		return true
	default:
		return false
	}
}

// reader is a bounds-checked cursor over the frame bytes.
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

func (r *reader) bytes(dst []byte) bool {
	if r.off+len(dst) > len(r.b) {
		return false
	}
	copy(dst, r.b[r.off:r.off+len(dst)])
	r.off += len(dst)
	return true
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

func (r *reader) u16() (uint16, bool) {
	if r.off+2 > len(r.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint16(r.b[r.off : r.off+2])
	r.off += 2
	return v, true
}
