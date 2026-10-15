package session

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
)

// SessionID is a 128-bit identifier chosen by the opener with crypto/rand and
// adopted by the responder. It is unguessable and collision-free across a pair
// (~2^-122 under simultaneous bidirectional opens), so it cannot be forged or
// collided onto another pair's session. Note that the SessionID is NOT the
// resume authority: resume is authorized by the Noise-authenticated peer
// identity (see package node), the SessionID only names the stream.
type SessionID [16]byte

// NewSessionID draws a fresh random SessionID.
func NewSessionID() (SessionID, error) {
	var s SessionID
	if _, err := rand.Read(s[:]); err != nil {
		return s, err
	}
	return s, nil
}

// String renders the SessionID as hex.
func (s SessionID) String() string { return hex.EncodeToString(s[:]) }

// Short renders the first 4 bytes of the SessionID as hex, for logs.
func (s SessionID) Short() string { return hex.EncodeToString(s[:4]) }

// IsZero reports whether the SessionID is all zero.
func (s SessionID) IsZero() bool {
	for _, b := range s {
		if b != 0 {
			return false
		}
	}
	return true
}

// Session sub-frame types. They live inside the Noise-sealed payload behind the
// node's msgSession (0x20) app type, so this codec encodes only the body
// (subtype + sessionID + type-specific fields). The node prepends msgSession.
const (
	subOpen      uint8 = 1
	subOpenAck   uint8 = 2
	subData      uint8 = 3
	subAck       uint8 = 4
	subResume    uint8 = 5
	subResumeAck uint8 = 6
	subFin       uint8 = 7
	subFinAck    uint8 = 8
	subReset     uint8 = 9
)

// RESET codes, carried in a subReset frame.
const (
	ResetProtocol uint8 = 1 // a cursor value violated the monotonic/bounded invariant
	ResetClosed   uint8 = 2 // the peer closed/aborted the session
)

// Frame is a decoded session sub-frame. Only the fields relevant to Sub are
// meaningful; the rest are zero.
type Frame struct {
	Sub     uint8
	Session SessionID

	// subData
	Offset uint64
	Data   []byte

	// subAck / subResume / subResumeAck
	AckOff uint64 // subAck: cumulative ack; subResume/Ack: sender's own rcvNxt
	RcvWnd uint32

	// subOpen / subOpenAck
	WinHint uint32

	// subFin / subFinAck
	FinOff uint64

	// subReset
	Code uint8
}

const sidLen = 16

// Encode serializes a Frame body (subtype + sessionID + fields). The node wraps
// it with the msgSession app type before sealing.
func Encode(f Frame) []byte {
	switch f.Sub {
	case subOpen, subOpenAck:
		b := make([]byte, 1+sidLen+4)
		b[0] = f.Sub
		copy(b[1:], f.Session[:])
		binary.BigEndian.PutUint32(b[1+sidLen:], f.WinHint)
		return b
	case subData:
		b := make([]byte, 1+sidLen+8+2+len(f.Data))
		b[0] = f.Sub
		copy(b[1:], f.Session[:])
		o := 1 + sidLen
		binary.BigEndian.PutUint64(b[o:], f.Offset)
		binary.BigEndian.PutUint16(b[o+8:], uint16(len(f.Data)))
		copy(b[o+10:], f.Data)
		return b
	case subAck, subResume, subResumeAck:
		b := make([]byte, 1+sidLen+8+4)
		b[0] = f.Sub
		copy(b[1:], f.Session[:])
		o := 1 + sidLen
		binary.BigEndian.PutUint64(b[o:], f.AckOff)
		binary.BigEndian.PutUint32(b[o+8:], f.RcvWnd)
		return b
	case subFin, subFinAck:
		b := make([]byte, 1+sidLen+8)
		b[0] = f.Sub
		copy(b[1:], f.Session[:])
		binary.BigEndian.PutUint64(b[1+sidLen:], f.FinOff)
		return b
	case subReset:
		b := make([]byte, 1+sidLen+1)
		b[0] = f.Sub
		copy(b[1:], f.Session[:])
		b[1+sidLen] = f.Code
		return b
	default:
		return nil
	}
}

// Decode parses a Frame body. It validates length BEFORE reading fields (mirror
// of swim/codec.go) and copies the DATA payload so it never retains a sub-slice
// of a decrypt buffer. ok is false for a malformed/unknown frame.
func Decode(b []byte) (Frame, bool) {
	if len(b) < 1+sidLen {
		return Frame{}, false
	}
	var f Frame
	f.Sub = b[0]
	copy(f.Session[:], b[1:1+sidLen])
	rest := b[1+sidLen:]
	switch f.Sub {
	case subOpen, subOpenAck:
		if len(rest) < 4 {
			return Frame{}, false
		}
		f.WinHint = binary.BigEndian.Uint32(rest)
		return f, true
	case subData:
		if len(rest) < 10 {
			return Frame{}, false
		}
		f.Offset = binary.BigEndian.Uint64(rest)
		n := int(binary.BigEndian.Uint16(rest[8:]))
		if len(rest) < 10+n {
			return Frame{}, false
		}
		f.Data = append([]byte(nil), rest[10:10+n]...)
		return f, true
	case subAck, subResume, subResumeAck:
		if len(rest) < 12 {
			return Frame{}, false
		}
		f.AckOff = binary.BigEndian.Uint64(rest)
		f.RcvWnd = binary.BigEndian.Uint32(rest[8:])
		return f, true
	case subFin, subFinAck:
		if len(rest) < 8 {
			return Frame{}, false
		}
		f.FinOff = binary.BigEndian.Uint64(rest)
		return f, true
	case subReset:
		if len(rest) < 1 {
			return Frame{}, false
		}
		f.Code = rest[0]
		return f, true
	default:
		return Frame{}, false
	}
}

// IsOpen reports whether the frame is an OPEN (the only sub-type that may create
// a new session on the responder).
func (f Frame) IsOpen() bool { return f.Sub == subOpen }

// ResetFrame builds a RESET frame for a session id with the given code.
func ResetFrame(id SessionID, code uint8) Frame {
	return Frame{Sub: subReset, Session: id, Code: code}
}

// PeekSessionID extracts the SessionID from an encoded session body without a
// full decode, so the node can route a frame to the right session (and enforce
// the identity guard) before stepping the state machine. ok is false if the
// body is too short to carry a subtype + id.
func PeekSessionID(b []byte) (uint8, SessionID, bool) {
	if len(b) < 1+sidLen {
		return 0, SessionID{}, false
	}
	var s SessionID
	copy(s[:], b[1:1+sidLen])
	return b[0], s, true
}
