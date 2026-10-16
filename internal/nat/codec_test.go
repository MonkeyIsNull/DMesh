package nat

import (
	"net/netip"
	"testing"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
)

func TestReflexCodec(t *testing.T) {
	if m, ok := DecodeReflex(EncodeReflexReq()); !ok || m.Sub != ReflexReq {
		t.Fatalf("reflexReq round-trip failed: %+v ok=%v", m, ok)
	}
	obs := ap("203.0.113.7:4500")
	m, ok := DecodeReflex(EncodeReflexResp(obs))
	if !ok || m.Sub != ReflexResp || m.Observed != obs {
		t.Fatalf("reflexResp round-trip failed: %+v ok=%v", m, ok)
	}
	// Unknown version / truncation / unknown sub all drop cleanly.
	if _, ok := DecodeReflex([]byte{2, ReflexReq}); ok {
		t.Fatal("unknown version accepted")
	}
	if _, ok := DecodeReflex([]byte{natVersion}); ok {
		t.Fatal("truncated accepted")
	}
	if _, ok := DecodeReflex([]byte{natVersion, 99}); ok {
		t.Fatal("unknown sub accepted")
	}
	if _, ok := DecodeReflex(nil); ok {
		t.Fatal("empty accepted")
	}
}

func TestRelayCodec(t *testing.T) {
	var target, source identity.NodeID
	target[0], target[31] = 1, 2
	source[0], source[31] = 3, 4

	cases := [][]byte{
		EncodeCircOpen(target, 0xdeadbeef),
		EncodeCircOpenAck(0xdeadbeef, CircStatusOK, CircuitID(0x1122334455667788)),
		EncodeCircOpenNotify(source, CircuitID(42)),
		EncodeCircData(CircuitID(42), []byte("inner-opaque-datagram")),
		EncodeCircClose(CircuitID(42), 7),
	}
	for i, b := range cases {
		m, ok := DecodeRelay(b)
		if !ok {
			t.Fatalf("case %d failed to decode", i)
		}
		switch m.Sub {
		case CircOpen:
			if m.Target != target || m.ReqNonce != 0xdeadbeef {
				t.Fatalf("circOpen fields wrong: %+v", m)
			}
		case CircOpenAck:
			if m.ReqNonce != 0xdeadbeef || m.Status != CircStatusOK || m.CircuitID != 0x1122334455667788 {
				t.Fatalf("circOpenAck fields wrong: %+v", m)
			}
		case CircOpenNotify:
			if m.Source != source || m.CircuitID != 42 {
				t.Fatalf("circOpenNotify fields wrong: %+v", m)
			}
		case CircData:
			if m.CircuitID != 42 || string(m.Payload) != "inner-opaque-datagram" {
				t.Fatalf("circData fields wrong: %+v", m)
			}
		case CircClose:
			if m.CircuitID != 42 || m.Code != 7 {
				t.Fatalf("circClose fields wrong: %+v", m)
			}
		}
	}
	// Forward-compat and bounds: unknown version/sub + every truncation drop
	// cleanly (no panic, ok=false).
	if _, ok := DecodeRelay([]byte{2, CircOpen}); ok {
		t.Fatal("unknown relay version accepted")
	}
	if _, ok := DecodeRelay([]byte{relayVersion, 99}); ok {
		t.Fatal("unknown relay sub accepted")
	}
	full := EncodeCircOpenAck(1, 0, 2)
	for n := 0; n < len(full); n++ {
		if _, ok := DecodeRelay(full[:n]); ok {
			t.Fatalf("truncation at %d accepted", n)
		}
	}
}

func TestCandExtCodec(t *testing.T) {
	id := mustID(t, 11)
	set := SignSelf(id, 3, CapNat, []Candidate{
		{Addr: ap("203.0.113.1:1"), Type: CandHost},
		{Addr: ap("198.51.100.9:4500"), Type: CandReflexive},
	})
	members := []CandMember{{Subject: id.NodeID(), Set: set}}

	enc := EncodeCandExt(members, 6)
	// EncodedCandMemberLen must match the per-member wire length.
	want := 3 + EncodedCandMemberLen(members[0], 6) // marker+ver+count + member
	if len(enc) != want {
		t.Fatalf("EncodeCandExt len %d != predicted %d", len(enc), want)
	}

	got, ok := DecodeCandExt(enc)
	if !ok || len(got) != 1 {
		t.Fatalf("decode failed ok=%v n=%d", ok, len(got))
	}
	if got[0].Subject != id.NodeID() {
		t.Fatal("subject mismatch")
	}
	if !Verify(got[0].Subject, got[0].Set) {
		t.Fatal("decoded member did not verify")
	}

	// Unknown marker/version and truncation drop cleanly.
	if _, ok := DecodeCandExt([]byte{0x00, candExtVer, 0}); ok {
		t.Fatal("unknown marker accepted")
	}
	if _, ok := DecodeCandExt([]byte{candExtMarker, 2, 0}); ok {
		t.Fatal("unknown ext version accepted")
	}
	for n := 0; n < len(enc); n++ {
		if _, ok := DecodeCandExt(enc[:n]); ok {
			t.Fatalf("truncation at %d accepted", n)
		}
	}
}

func TestFindCandExt(t *testing.T) {
	swimPart := []byte{1, 2, 3, 4, 5}
	ext := EncodeCandExt(nil, 6)
	full := append(append([]byte(nil), swimPart...), ext...)
	off, ok := FindCandExt(full, len(swimPart))
	if !ok || off != len(swimPart) {
		t.Fatalf("FindCandExt off=%d ok=%v", off, ok)
	}
	// No extension present.
	if _, ok := FindCandExt(swimPart, len(swimPart)); ok {
		t.Fatal("FindCandExt false positive on exact-length payload")
	}
}

func TestEndpointLen(t *testing.T) {
	if endpointLen(netip.AddrPort{}) != 1 {
		t.Fatal("invalid endpoint len")
	}
	if endpointLen(ap("1.2.3.4:5")) != 7 {
		t.Fatal("v4 endpoint len")
	}
	if endpointLen(ap("[2001:db8::1]:5")) != 19 {
		t.Fatal("v6 endpoint len")
	}
}
