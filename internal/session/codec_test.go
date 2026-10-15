package session

import (
	"bytes"
	"testing"
)

func TestCodecRoundTrip(t *testing.T) {
	sid, _ := NewSessionID()
	cases := []Frame{
		{Sub: subOpen, Session: sid, WinHint: 65536},
		{Sub: subOpenAck, Session: sid, WinHint: 12345},
		{Sub: subData, Session: sid, Offset: 1 << 40, Data: []byte("hello world payload")},
		{Sub: subAck, Session: sid, AckOff: 999999, RcvWnd: 4096},
		{Sub: subResume, Session: sid, AckOff: 42, RcvWnd: 8192},
		{Sub: subResumeAck, Session: sid, AckOff: 77, RcvWnd: 1},
		{Sub: subFin, Session: sid, FinOff: 123456},
		{Sub: subFinAck, Session: sid, FinOff: 123456},
		{Sub: subReset, Session: sid, Code: ResetProtocol},
	}
	for _, c := range cases {
		enc := Encode(c)
		got, ok := Decode(enc)
		if !ok {
			t.Fatalf("decode failed for sub %d", c.Sub)
		}
		if got.Sub != c.Sub || got.Session != c.Session {
			t.Fatalf("sub/session mismatch: %+v vs %+v", got, c)
		}
		if got.Offset != c.Offset || got.AckOff != c.AckOff || got.WinHint != c.WinHint ||
			got.RcvWnd != c.RcvWnd || got.FinOff != c.FinOff || got.Code != c.Code {
			t.Fatalf("field mismatch for sub %d: %+v vs %+v", c.Sub, got, c)
		}
		if !bytes.Equal(got.Data, c.Data) {
			t.Fatalf("data mismatch for sub %d: %q vs %q", c.Sub, got.Data, c.Data)
		}
		// Peek must agree with decode.
		sub, psid, ok := PeekSessionID(enc)
		if !ok || sub != c.Sub || psid != c.Session {
			t.Fatalf("peek mismatch for sub %d", c.Sub)
		}
	}
	// Truncated frames must be rejected, not panic.
	if _, ok := Decode([]byte{subData}); ok {
		t.Fatal("short frame accepted")
	}
	if _, ok := Decode(nil); ok {
		t.Fatal("nil frame accepted")
	}
}
