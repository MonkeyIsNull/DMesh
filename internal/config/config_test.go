package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
)

func TestNetworkKeyRoundTripAndValidation(t *testing.T) {
	c := OpenAt(t.TempDir())

	// Absent key => (nil, nil); caller must fail closed.
	key, err := c.LoadNetworkKey()
	if err != nil || key != nil {
		t.Fatalf("absent key: %v %v", key, err)
	}

	good := make([]byte, NetworkKeyLen)
	for i := range good {
		good[i] = byte(i)
	}
	if err := c.SaveNetworkKey(good); err != nil {
		t.Fatal(err)
	}
	got, err := c.LoadNetworkKey()
	if err != nil {
		t.Fatal(err)
	}
	if !KeysEqual(got, good) {
		t.Fatal("round-trip mismatch")
	}

	// Wrong length rejected on save.
	if err := c.SaveNetworkKey(make([]byte, 16)); err == nil {
		t.Fatal("16-byte key saved")
	}

	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(filepath.Join(c.Dir(), networkKeyFile))
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("network key perm = %o, want 600", fi.Mode().Perm())
		}
	}

	if err := c.ClearNetworkKey(); err != nil {
		t.Fatal(err)
	}
	if key, _ := c.LoadNetworkKey(); key != nil {
		t.Fatal("key present after clear")
	}
}

func TestNetworkKeyEnvFallback(t *testing.T) {
	c := OpenAt(t.TempDir())
	good := make([]byte, NetworkKeyLen)
	t.Setenv(EnvNetworkKey, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	key, err := c.LoadNetworkKey()
	if err != nil {
		t.Fatal(err)
	}
	if !KeysEqual(key, good) {
		t.Fatal("env key not loaded as fallback")
	}
}

func TestConfigDirOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvConfigDir, dir)

	// Dir() returns the override verbatim (dirName is not appended).
	got, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	if got != dir {
		t.Fatalf("Dir() = %q, want %q", got, dir)
	}

	// Open() roots the handle at the override, so every file resolves under it.
	c, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	if c.Dir() != dir {
		t.Fatalf("Open().Dir() = %q, want %q", c.Dir(), dir)
	}
	for _, p := range []string{c.IdentityPath(), c.IncarnationPath()} {
		if filepath.Dir(p) != dir {
			t.Fatalf("path %q not under override dir %q", p, dir)
		}
	}

	// The network key also lands under the override.
	good := make([]byte, NetworkKeyLen)
	if err := c.SaveNetworkKey(good); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, networkKeyFile)); err != nil {
		t.Fatalf("network key not written under override dir: %v", err)
	}
}

func TestTrustListRoundTrip(t *testing.T) {
	c := OpenAt(t.TempDir())
	id1 := mustID(t)
	id2 := mustID(t)

	if err := c.Trust(id1, "one"); err != nil {
		t.Fatal(err)
	}
	if err := c.Trust(id2, ""); err != nil {
		t.Fatal(err)
	}
	tl, err := c.LoadTrust()
	if err != nil {
		t.Fatal(err)
	}
	if len(tl.Entries) != 2 {
		t.Fatalf("got %d entries", len(tl.Entries))
	}

	// Garbage / truncated node IDs are rejected cleanly.
	if err := c.Trust("not-a-valid-id", ""); err == nil {
		t.Fatal("garbage node ID trusted")
	}

	if err := c.Untrust(id1); err != nil {
		t.Fatal(err)
	}
	tl, _ = c.LoadTrust()
	if len(tl.Entries) != 1 || tl.Entries[0].NodeID != id2 {
		t.Fatalf("untrust left %+v", tl.Entries)
	}
}

func mustID(t *testing.T) string {
	t.Helper()
	id, err := identity.Generate("")
	if err != nil {
		t.Fatal(err)
	}
	return id.NodeID().String()
}

func TestFingerprintNeverLeaksSecret(t *testing.T) {
	key := make([]byte, NetworkKeyLen)
	for i := range key {
		key[i] = 0xAB
	}
	fp := Fingerprint(key)
	if len(fp) != 8 {
		t.Fatalf("fingerprint = %q", fp)
	}
	if Fingerprint(nil) != "(none)" {
		t.Fatal("nil fingerprint")
	}
}
