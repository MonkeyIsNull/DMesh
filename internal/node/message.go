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
)

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
