package transport

import (
	"encoding/binary"
	"errors"
)

// Wire framing. Two frame types share a 2-byte magic + 1-byte version + 1-byte
// type prefix so a single UDP socket can demux them. The 4-byte connection
// index (WireGuard-style) reserves the identity-not-address seam now: each side
// picks a random local index at handshake start and advertises it as
// senderIndex in handshake frames; data frames carry the peer-assigned
// receiverIndex, so a socket can demux peers independent of source address.
//
// Handshake frame: magic(2) version(1) type(1) hsIndex(1) senderIndex(4) len(2) noiseMsg
// Data frame:      magic(2) version(1) type(1) flags(1)  receiverIndex(4) nonce(8) len(2) ciphertext
const (
	magic0 = 0xD3
	magic1 = 0x5A

	WireVersion = 1

	typeHandshake = 1
	typeData      = 2

	hsHeaderLen   = 2 + 1 + 1 + 1 + 4 + 2     // 11
	dataHeaderLen = 2 + 1 + 1 + 1 + 4 + 8 + 2 // 19

	// MaxPayload caps a single-datagram payload (handshake message or data
	// ciphertext). It bounds every length-prefixed slice before allocation so a
	// forged length can never trigger a huge allocation or a panic. ~1200 bytes
	// keeps DMesh datagrams clear of common path-MTU fragmentation.
	MaxPayload = 1200

	// aeadOverhead is the Poly1305 tag Encrypt appends to the plaintext.
	aeadOverhead = 16

	// MaxPlaintext is the largest plaintext Seal accepts, so the resulting
	// ciphertext fits MaxPayload. The send-side cap mirrors the receive-side
	// decodeData cap, keeping the single-datagram invariant symmetric.
	MaxPlaintext = MaxPayload - aeadOverhead

	// MaxFrame is the largest datagram we ever read.
	MaxFrame = dataHeaderLen + MaxPayload
)

// Data frame flag bits.
const (
	flagNone = 0
)

var (
	errShort   = errors.New("transport: datagram too short")
	errMagic   = errors.New("transport: bad magic")
	errVersion = errors.New("transport: unsupported wire version")
	errType    = errors.New("transport: unknown frame type")
	errBadLen  = errors.New("transport: length field exceeds datagram or cap")
)

// Kind classifies a datagram.
type Kind int

const (
	// KindHandshake is a handshake frame.
	KindHandshake Kind = iota
	// KindData is an encrypted data frame.
	KindData
)

// Classify returns the kind of a datagram after validating its common header.
func Classify(b []byte) (Kind, error) {
	ft, err := frameType(b)
	if err != nil {
		return 0, err
	}
	if ft == typeHandshake {
		return KindHandshake, nil
	}
	return KindData, nil
}

// PeekHandshake reports whether b is a handshake frame and, if so, its message
// index (1, 2 or 3). It is used to decide whether an unsolicited datagram from
// an unknown source should start a responder handshake.
func PeekHandshake(b []byte) (hsIndex uint8, ok bool) {
	hf, err := asHandshake(b)
	if err != nil {
		return 0, false
	}
	return hf.hsIndex, true
}

// handshakeFrame is a decoded handshake datagram.
type handshakeFrame struct {
	hsIndex     uint8
	senderIndex uint32
	noiseMsg    []byte
}

// dataFrame is a decoded data datagram.
type dataFrame struct {
	flags         uint8
	receiverIndex uint32
	nonce         uint64
	ciphertext    []byte
}

// encodeHandshake serializes a handshake frame.
func encodeHandshake(hsIndex uint8, senderIndex uint32, noiseMsg []byte) []byte {
	buf := make([]byte, hsHeaderLen+len(noiseMsg))
	buf[0] = magic0
	buf[1] = magic1
	buf[2] = WireVersion
	buf[3] = typeHandshake
	buf[4] = hsIndex
	binary.BigEndian.PutUint32(buf[5:9], senderIndex)
	binary.BigEndian.PutUint16(buf[9:11], uint16(len(noiseMsg)))
	copy(buf[hsHeaderLen:], noiseMsg)
	return buf
}

// encodeData serializes a data frame.
func encodeData(flags uint8, receiverIndex uint32, nonce uint64, ciphertext []byte) []byte {
	buf := make([]byte, dataHeaderLen+len(ciphertext))
	buf[0] = magic0
	buf[1] = magic1
	buf[2] = WireVersion
	buf[3] = typeData
	buf[4] = flags
	binary.BigEndian.PutUint32(buf[5:9], receiverIndex)
	binary.BigEndian.PutUint64(buf[9:17], nonce)
	binary.BigEndian.PutUint16(buf[17:19], uint16(len(ciphertext)))
	copy(buf[dataHeaderLen:], ciphertext)
	return buf
}

// frameType peeks the type byte of a datagram after validating the common
// header. It returns typeHandshake or typeData, or an error.
func frameType(b []byte) (uint8, error) {
	if len(b) < 4 {
		return 0, errShort
	}
	if b[0] != magic0 || b[1] != magic1 {
		return 0, errMagic
	}
	if b[2] != WireVersion {
		return 0, errVersion
	}
	switch b[3] {
	case typeHandshake, typeData:
		return b[3], nil
	default:
		return 0, errType
	}
}

// decodeHandshake parses a handshake datagram, validating the length field
// against the actual datagram length and the single-datagram cap.
func decodeHandshake(b []byte) (handshakeFrame, error) {
	if len(b) < hsHeaderLen {
		return handshakeFrame{}, errShort
	}
	msgLen := int(binary.BigEndian.Uint16(b[9:11]))
	if msgLen > MaxPayload || hsHeaderLen+msgLen > len(b) {
		return handshakeFrame{}, errBadLen
	}
	msg := make([]byte, msgLen)
	copy(msg, b[hsHeaderLen:hsHeaderLen+msgLen])
	return handshakeFrame{
		hsIndex:     b[4],
		senderIndex: binary.BigEndian.Uint32(b[5:9]),
		noiseMsg:    msg,
	}, nil
}

// decodeData parses a data datagram, validating the length field against the
// actual datagram length and the single-datagram cap.
func decodeData(b []byte) (dataFrame, error) {
	if len(b) < dataHeaderLen {
		return dataFrame{}, errShort
	}
	ctLen := int(binary.BigEndian.Uint16(b[17:19]))
	if ctLen > MaxPayload || dataHeaderLen+ctLen > len(b) {
		return dataFrame{}, errBadLen
	}
	ct := make([]byte, ctLen)
	copy(ct, b[dataHeaderLen:dataHeaderLen+ctLen])
	return dataFrame{
		flags:         b[4],
		receiverIndex: binary.BigEndian.Uint32(b[5:9]),
		nonce:         binary.BigEndian.Uint64(b[9:17]),
		ciphertext:    ct,
	}, nil
}
