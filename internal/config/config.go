// Package config resolves DMesh's per-OS configuration directory and loads and
// saves the files that live there: the node identity, the pre-shared network
// key (the primary membership credential), and the trust allow-list (the
// secondary credential). All files are written 0600 inside a 0700 directory.
package config

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
)

const (
	dirName         = "dmesh"
	identityFile    = "identity.json"
	networkKeyFile  = "network.key"
	trustFile       = "trust.json"
	incarnationFile = "incarnation"

	dirPerm  os.FileMode = 0o700
	filePerm os.FileMode = 0o600

	// NetworkKeyLen is the required length of the pre-shared network key, fixed
	// by the Noise PSK requirement (flynn/noise SetPresharedKey wants 32 bytes).
	NetworkKeyLen = 32

	// EnvNetworkKey is a fallback source for the network key. The config file is
	// preferred; an environment variable can leak via /proc and inherited
	// environments.
	EnvNetworkKey = "DMESH_NETWORK_KEY"
)

// Dir resolves the DMesh config directory (e.g. ~/Library/Application
// Support/dmesh on macOS, $XDG_CONFIG_HOME/dmesh or ~/.config/dmesh on Linux).
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("config: resolve user config dir: %w", err)
	}
	return filepath.Join(base, dirName), nil
}

// Config binds a resolved config directory to its file paths.
type Config struct {
	dir string
}

// Open resolves the config directory and returns a handle to it. It does not
// create the directory; the first write does.
func Open() (*Config, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	return &Config{dir: dir}, nil
}

// OpenAt returns a handle rooted at an explicit directory (used by tests).
func OpenAt(dir string) *Config { return &Config{dir: dir} }

// Dir returns the config directory path.
func (c *Config) Dir() string { return c.dir }

// IdentityPath returns the path to the identity file.
func (c *Config) IdentityPath() string { return filepath.Join(c.dir, identityFile) }

// IncarnationPath returns the path to the persisted SWIM self-incarnation,
// stored beside the identity (they live or die together, which is what makes
// the restart/incarnation-reset fix sound).
func (c *Config) IncarnationPath() string { return filepath.Join(c.dir, incarnationFile) }

// LoadIdentity loads the node identity, generating and persisting one on first
// run. The bool reports whether a new identity was created.
func (c *Config) LoadIdentity(label string) (*identity.Identity, bool, error) {
	return identity.Load(c.IdentityPath(), label)
}

// --- network key -----------------------------------------------------------

// LoadNetworkKey returns the 32-byte pre-shared network key. It prefers the
// config file and falls back to EnvNetworkKey. It returns (nil, nil) when no
// key is configured anywhere; the caller MUST fail closed in that case. A
// present-but-malformed key is a hard error.
func (c *Config) LoadNetworkKey() ([]byte, error) {
	path := filepath.Join(c.dir, networkKeyFile)
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		return decodeNetworkKey(strings.TrimSpace(string(data)))
	case errors.Is(err, os.ErrNotExist):
		if v := strings.TrimSpace(os.Getenv(EnvNetworkKey)); v != "" {
			return decodeNetworkKey(v)
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("config: read network key: %w", err)
	}
}

// decodeNetworkKey parses a base64 network key and validates its length.
func decodeNetworkKey(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("config: network key is not valid base64: %w", err)
	}
	if len(raw) != NetworkKeyLen {
		return nil, fmt.Errorf("config: network key must be %d bytes, got %d", NetworkKeyLen, len(raw))
	}
	return raw, nil
}

// SaveNetworkKey validates and stores a network key (base64-encoded) at 0600.
func (c *Config) SaveNetworkKey(key []byte) error {
	if len(key) != NetworkKeyLen {
		return fmt.Errorf("config: network key must be %d bytes, got %d", NetworkKeyLen, len(key))
	}
	if err := os.MkdirAll(c.dir, dirPerm); err != nil {
		return fmt.Errorf("config: mkdir: %w", err)
	}
	enc := base64.StdEncoding.EncodeToString(key)
	return atomicWrite(filepath.Join(c.dir, networkKeyFile), []byte(enc+"\n"))
}

// ClearNetworkKey removes the stored network key, if any.
func (c *Config) ClearNetworkKey() error {
	err := os.Remove(filepath.Join(c.dir, networkKeyFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("config: clear network key: %w", err)
	}
	return nil
}

// Fingerprint returns a short, non-secret fingerprint of a key for display.
// The secret itself is never printed. Returns "(none)" for an absent key.
func Fingerprint(key []byte) string {
	if len(key) == 0 {
		return "(none)"
	}
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:4])
}

// KeysEqual reports whether two keys are equal in constant time.
func KeysEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// --- trust allow-list -------------------------------------------------------

// TrustEntry is one allow-listed node.
type TrustEntry struct {
	NodeID string `json:"node_id"`
	Label  string `json:"label,omitempty"`
}

// TrustList is the persisted allow-list. An empty list means trust-on-first-use
// (accept any peer that proved the network key); a non-empty list restricts
// trust to exactly the listed node IDs.
type TrustList struct {
	Entries []TrustEntry `json:"entries"`
}

// LoadTrust loads the allow-list, returning an empty list if none exists.
func (c *Config) LoadTrust() (*TrustList, error) {
	data, err := os.ReadFile(filepath.Join(c.dir, trustFile))
	if errors.Is(err, os.ErrNotExist) {
		return &TrustList{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("config: read trust list: %w", err)
	}
	var tl TrustList
	if err := json.Unmarshal(data, &tl); err != nil {
		return nil, fmt.Errorf("config: parse trust list: %w", err)
	}
	return &tl, nil
}

// SaveTrust writes the allow-list atomically at 0600.
func (c *Config) SaveTrust(tl *TrustList) error {
	if err := os.MkdirAll(c.dir, dirPerm); err != nil {
		return fmt.Errorf("config: mkdir: %w", err)
	}
	data, err := json.MarshalIndent(tl, "", "  ")
	if err != nil {
		return fmt.Errorf("config: marshal trust list: %w", err)
	}
	return atomicWrite(filepath.Join(c.dir, trustFile), data)
}

// Trust adds (or relabels) a node ID. The id must be a valid full node ID.
func (c *Config) Trust(id, label string) error {
	nid, err := identity.ParseNodeID(id)
	if err != nil {
		return err
	}
	tl, err := c.LoadTrust()
	if err != nil {
		return err
	}
	full := nid.String()
	for i := range tl.Entries {
		if tl.Entries[i].NodeID == full {
			tl.Entries[i].Label = label
			return c.SaveTrust(tl)
		}
	}
	tl.Entries = append(tl.Entries, TrustEntry{NodeID: full, Label: label})
	sort.Slice(tl.Entries, func(i, j int) bool { return tl.Entries[i].NodeID < tl.Entries[j].NodeID })
	return c.SaveTrust(tl)
}

// Untrust removes a node ID from the allow-list.
func (c *Config) Untrust(id string) error {
	nid, err := identity.ParseNodeID(id)
	if err != nil {
		return err
	}
	tl, err := c.LoadTrust()
	if err != nil {
		return err
	}
	full := nid.String()
	out := tl.Entries[:0]
	for _, e := range tl.Entries {
		if e.NodeID != full {
			out = append(out, e)
		}
	}
	tl.Entries = out
	return c.SaveTrust(tl)
}

// atomicWrite writes data via a temp file + rename, with 0600 perms.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("config: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(filePerm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
