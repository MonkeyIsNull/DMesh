package identity

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGenerateAndNodeID(t *testing.T) {
	id, err := Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	nid := id.NodeID()
	if nid.IsZero() {
		t.Fatal("node ID is zero")
	}
	if len(id.NoiseStatic.Public) != 32 || len(id.NoiseStatic.Private) != 32 {
		t.Fatalf("bad x25519 key lengths: pub=%d priv=%d", len(id.NoiseStatic.Public), len(id.NoiseStatic.Private))
	}
	if id.Label != "alice" {
		t.Fatalf("label = %q", id.Label)
	}
}

func TestNodeIDEncodeDecodeRoundTrip(t *testing.T) {
	id, _ := Generate("")
	nid := id.NodeID()
	s := nid.String()
	if len(s) != 52 {
		t.Fatalf("encoded node ID = %d chars, want 52: %q", len(s), s)
	}
	got, err := ParseNodeID(s)
	if err != nil {
		t.Fatal(err)
	}
	if got != nid {
		t.Fatal("round-trip mismatch")
	}
	// Short is display-only and must never be used for matching.
	if len(nid.Short()) != 10 {
		t.Fatalf("short = %q", nid.Short())
	}
}

func TestParseNodeIDNegative(t *testing.T) {
	cases := map[string]string{
		"empty":        "",
		"not base32":   "!!!!notbase32!!!!",
		"wrong length": "aaaa",
		"all zero":     NodeID{}.String(),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseNodeID(in); err == nil {
				t.Fatalf("ParseNodeID(%q) succeeded, want error", in)
			}
		})
	}
}

func TestBindingSignVerify(t *testing.T) {
	id, _ := Generate("")
	edPub := id.Signing.Public().(ed25519.PublicKey)
	sig := id.SignBinding()

	if !VerifyBinding(edPub, id.NoiseStatic.Public, sig) {
		t.Fatal("valid binding failed to verify")
	}
	// Wrong X25519 static must fail.
	other, _ := Generate("")
	if VerifyBinding(edPub, other.NoiseStatic.Public, sig) {
		t.Fatal("binding verified against the wrong static")
	}
	// Wrong Ed25519 key must fail.
	if VerifyBinding(other.Signing.Public().(ed25519.PublicKey), id.NoiseStatic.Public, sig) {
		t.Fatal("binding verified against the wrong signing key")
	}
	// Tampered signature must fail.
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0xff
	if VerifyBinding(edPub, id.NoiseStatic.Public, bad) {
		t.Fatal("tampered signature verified")
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "identity.json")

	id, created, err := Load(path, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("first Load should report created=true")
	}

	id2, created2, err := Load(path, "ignored-on-reload")
	if err != nil {
		t.Fatal(err)
	}
	if created2 {
		t.Fatal("second Load should report created=false")
	}
	if id2.NodeID() != id.NodeID() {
		t.Fatal("reloaded node ID differs")
	}
	if string(id2.NoiseStatic.Private) != string(id.NoiseStatic.Private) {
		t.Fatal("reloaded x25519 private differs")
	}
	if string(id2.NoiseStatic.Public) != string(id.NoiseStatic.Public) {
		t.Fatal("reloaded x25519 public differs")
	}
	if id2.Label != "bob" {
		t.Fatalf("reloaded label = %q, want bob", id2.Label)
	}
	// Binding must still verify after reload.
	if !VerifyBinding(id2.NodeID().Ed25519(), id2.NoiseStatic.Public, id2.SignBinding()) {
		t.Fatal("binding broken after reload")
	}
}

func TestPersistencePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := t.TempDir()
	sub := filepath.Join(dir, "cfg")
	path := filepath.Join(sub, "identity.json")
	if _, _, err := Load(path, ""); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("file perm = %o, want 600", fi.Mode().Perm())
	}
	di, err := os.Stat(sub)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir perm = %o, want 700", di.Mode().Perm())
	}
	// No leftover temp files from the atomic write.
	entries, _ := os.ReadDir(sub)
	for _, e := range entries {
		if e.Name() != "identity.json" {
			t.Fatalf("unexpected leftover file: %s", e.Name())
		}
	}
}

func TestLabelClamp(t *testing.T) {
	long := make([]byte, MaxLabelLen+50)
	for i := range long {
		long[i] = 'x'
	}
	id, _ := Generate(string(long))
	if len(id.Label) != MaxLabelLen {
		t.Fatalf("label len = %d, want %d", len(id.Label), MaxLabelLen)
	}
}
