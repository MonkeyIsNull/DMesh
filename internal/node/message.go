package node

// Application messages ride inside the encrypted session channel. The first
// byte is the message type; the remainder is type-specific. These are the
// minimal v0.1 set: a HELLO to populate the peer table, a keep-alive to refresh
// last-seen, and a text/ping to prove the channel.
const (
	msgHello     = 1
	msgKeepalive = 2
	msgPing      = 3
	msgText      = 4

	// msgSwim carries a SWIM membership envelope (see internal/swim/codec.go).
	// The range 0x10..0x1F is reserved for membership so future SWIM sub-types
	// never collide with the v0.1 app messages (1..4).
	msgSwim = 0x10

	// msgSession carries a durable-session sub-frame (see internal/session). The
	// range 0x20..0x2F is reserved for the session layer; the body is a
	// session.Encode'd frame (subtype + sessionID + fields).
	msgSession = 0x20

	// msgNat carries a v0.4 NAT reflex sub-protocol body (see internal/nat
	// codec.go). msgRelay carries a v0.4 circuit-control body. The range
	// 0x30..0x3F is reserved for NAT/relay so these never collide with the v0.1
	// app messages (1..4), SWIM (0x10..0x1F), or sessions (0x20..0x2F). Both are
	// versioned in their bodies and degrade to a harmless lsUpdate on a v0.3 peer
	// (handleApp's else-branch), preserving wire compatibility.
	msgNat   = 0x30
	msgRelay = 0x31
)

// encodeSession wraps an encoded session sub-frame body in the msgSession app
// type.
func encodeSession(body []byte) []byte {
	return append([]byte{msgSession}, body...)
}

// encodeSwim wraps an encoded SWIM envelope body in the msgSwim app type.
func encodeSwim(body []byte) []byte {
	return append([]byte{msgSwim}, body...)
}

// encodeNat wraps a NAT reflex sub-protocol body in the msgNat app type.
func encodeNat(body []byte) []byte {
	return append([]byte{msgNat}, body...)
}

// encodeRelay wraps a circuit-control body in the msgRelay app type.
func encodeRelay(body []byte) []byte {
	return append([]byte{msgRelay}, body...)
}

// encodeHello builds a HELLO carrying this node's label. The node ID is already
// authenticated by the handshake, so it is not repeated here.
func encodeHello(label string) []byte {
	return append([]byte{msgHello}, []byte(label)...)
}

func encodeKeepalive() []byte { return []byte{msgKeepalive} }

func encodePing() []byte { return []byte{msgPing} }

func encodeText(s string) []byte { return append([]byte{msgText}, []byte(s)...) }

// decoded is a parsed application message.
type decoded struct {
	typ  byte
	body []byte
}

func decodeMessage(b []byte) (decoded, bool) {
	if len(b) == 0 {
		return decoded{}, false
	}
	return decoded{typ: b[0], body: b[1:]}, true
}
