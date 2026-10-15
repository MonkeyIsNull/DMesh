package transport

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestHandshakeFrameRoundTrip(t *testing.T) {
	msg := []byte("noise-handshake-bytes")
	frame := encodeHandshake(2, 0xDEADBEEF, msg)

	kind, err := Classify(frame)
	if err != nil || kind != KindHandshake {
		t.Fatalf("Classify = %v, %v", kind, err)
	}
	idx, ok := PeekHandshake(frame)
	if !ok || idx != 2 {
		t.Fatalf("PeekHandshake = %d, %v", idx, ok)
	}
	hf, err := decodeHandshake(frame)
	if err != nil {
		t.Fatal(err)
	}
	if hf.hsIndex != 2 || hf.senderIndex != 0xDEADBEEF || !bytes.Equal(hf.noiseMsg, msg) {
		t.Fatalf("decoded = %+v", hf)
	}
}

func TestDataFrameRoundTrip(t *testing.T) {
	ct := []byte("ciphertext-with-tag")
	frame := encodeData(flagNone, 0x01020304, 0x1122334455667788, ct)

	kind, err := Classify(frame)
	if err != nil || kind != KindData {
		t.Fatalf("Classify = %v, %v", kind, err)
	}
	df, err := decodeData(frame)
	if err != nil {
		t.Fatal(err)
	}
	if df.receiverIndex != 0x01020304 || df.nonce != 0x1122334455667788 || !bytes.Equal(df.ciphertext, ct) {
		t.Fatalf("decoded = %+v", df)
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	if _, err := decodeHandshake([]byte{0x00}); err == nil {
		t.Fatal("short datagram accepted")
	}
	if _, err := Classify([]byte{0x00, 0x00, WireVersion, typeData}); err == nil {
		t.Fatal("bad magic accepted")
	}
	badVer := encodeData(flagNone, 1, 1, []byte("x"))
	badVer[2] = 0xFF
	if _, err := Classify(badVer); err == nil {
		t.Fatal("bad version accepted")
	}
}

func TestDecodeRejectsOversizeLength(t *testing.T) {
	// A data frame claiming 65535 bytes of ciphertext in a tiny datagram must be
	// dropped cheaply, never panic or over-allocate.
	frame := encodeData(flagNone, 1, 1, []byte("tiny"))
	binary.BigEndian.PutUint16(frame[17:19], 65535)
	if _, err := decodeData(frame); err != errBadLen {
		t.Fatalf("err = %v, want errBadLen", err)
	}

	// A handshake frame with a length over the single-datagram cap.
	hf := encodeHandshake(1, 1, []byte("tiny"))
	binary.BigEndian.PutUint16(hf[9:11], MaxPayload+1)
	if _, err := decodeHandshake(hf); err != errBadLen {
		t.Fatalf("err = %v, want errBadLen", err)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(encodeHandshake(1, 7, []byte("abc")))
	f.Add(encodeData(flagNone, 7, 9, []byte("abc")))
	f.Add([]byte{0xD3, 0x5A, 0x01, 0x02})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		// None of these may panic on arbitrary input.
		kind, err := Classify(b)
		if err != nil {
			return
		}
		switch kind {
		case KindHandshake:
			_, _ = decodeHandshake(b)
			_, _ = PeekHandshake(b)
		case KindData:
			_, _ = decodeData(b)
		}
	})
}
