// Package identity defines a DMesh node's cryptographic identity.
//
// A node identity is an Ed25519 keypair; the node ID is the 32-byte Ed25519
// public key, encoded for display as lowercase unpadded base32 (RFC 4648).
// Ed25519 is the canonical *signing* identity and the root for the later
// signed-invite / CA milestone.
//
// A separate X25519 keypair is the Noise static Diffie-Hellman key. The two
// keys are deliberately NOT derived from one another (no Ed25519->X25519
// birational conversion): they are *bound* by an Ed25519 signature over a
// domain-separated context string concatenated with the raw X25519 static
// public key. See package transport for the binding verification.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/flynn/noise"
)

// IDContext is the fixed domain-separation string signed, together with the
// raw 32-byte X25519 static public key, to bind the Noise static DH key to the
// Ed25519 signing identity. It is load-bearing: changing it invalidates every
// previously produced binding signature, and the verifier rejects a signature
// produced under any other context (tested).
const IDContext = "DMesh-v1 identity-binding"

// MaxLabelLen bounds a human label, keeping mDNS TXT records well under the
// 255-byte per-string cap.
const MaxLabelLen = 32

// nodeEnc is the canonical node-ID encoding: lowercase base32 without padding.
// A 32-byte key encodes to 52 characters, which fits a single 63-octet DNS
// label and contains no easily-confused characters.
var nodeEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// Identity is a node's persistent cryptographic material.
type Identity struct {
	// Signing is the Ed25519 private key; its public half is the node ID.
	Signing ed25519.PrivateKey
	// NoiseStatic is the X25519 static keypair used as the Noise static DH key.
	NoiseStatic noise.DHKey
	// Label is an optional human-friendly name (clamped to MaxLabelLen).
	Label string
}

// NodeID is a node identifier: the 32-byte Ed25519 public key.
type NodeID [32]byte

// nodeIDLen is the raw byte length of a node ID.
const nodeIDLen = 32

// NodeID returns this identity's node ID.
func (id *Identity) NodeID() NodeID {
	var n NodeID
	copy(n[:], id.Signing.Public().(ed25519.PublicKey))
	return n
}

// String returns the canonical lowercase unpadded-base32 encoding of the node
// ID. Policy matching (trust lists, self-filtering) always uses this full form.
func (n NodeID) String() string {
	return nodeEnc.EncodeToString(n[:])
}

// Short returns a truncated node ID for display in tables. It is NEVER used for
// matching; trust and policy compare the full String form only.
func (n NodeID) Short() string {
	s := n.String()
	if len(s) > 10 {
		return s[:10]
	}
	return s
}

// Ed25519 returns the node ID as an ed25519.PublicKey.
func (n NodeID) Ed25519() ed25519.PublicKey {
	pk := make(ed25519.PublicKey, nodeIDLen)
	copy(pk, n[:])
	return pk
}

// IsZero reports whether the node ID is all zero (never a valid identity).
func (n NodeID) IsZero() bool {
	var zero NodeID
	return n == zero
}

// ParseNodeID decodes a canonical node-ID string. It rejects non-base32 input,
// a wrong decoded length, and the all-zero key, returning a clean error rather
// than panicking or yielding a silent zero value.
func ParseNodeID(s string) (NodeID, error) {
	var n NodeID
	if s == "" {
		return n, errors.New("identity: empty node ID")
	}
	raw, err := nodeEnc.DecodeString(s)
	if err != nil {
		return n, fmt.Errorf("identity: not valid base32: %w", err)
	}
	if len(raw) != nodeIDLen {
		return n, fmt.Errorf("identity: wrong node-ID length: got %d bytes, want %d", len(raw), nodeIDLen)
	}
	copy(n[:], raw)
	if n.IsZero() {
		return NodeID{}, errors.New("identity: all-zero node ID is not valid")
	}
	return n, nil
}

// Generate creates a fresh identity from crypto/rand.
func Generate(label string) (*Identity, error) {
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: ed25519 keygen: %w", err)
	}
	dh, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: x25519 keygen: %w", err)
	}
	return &Identity{Signing: sk, NoiseStatic: dh, Label: clampLabel(label)}, nil
}

// clampLabel trims a label to MaxLabelLen bytes (on a UTF-8 boundary where
// possible is not required for v0.1; a byte clamp keeps the TXT record bounded).
func clampLabel(s string) string {
	if len(s) > MaxLabelLen {
		return s[:MaxLabelLen]
	}
	return s
}

// SignBinding returns an Ed25519 signature over IDContext || X25519-static-pub.
// It is the only custom crypto glue in DMesh and is verified in package
// transport against the X25519 static that Noise itself authenticated.
func (id *Identity) SignBinding() []byte {
	return ed25519.Sign(id.Signing, bindingMessage(id.NoiseStatic.Public))
}

// bindingMessage builds the exact bytes signed/verified for the identity
// binding: the fixed context string followed by the raw X25519 static pubkey.
func bindingMessage(x25519Pub []byte) []byte {
	msg := make([]byte, 0, len(IDContext)+len(x25519Pub))
	msg = append(msg, []byte(IDContext)...)
	msg = append(msg, x25519Pub...)
	return msg
}

// VerifyBinding checks a binding signature claiming that the Ed25519 key
// edPub vouches for the X25519 static x25519Pub. The caller MUST pass the
// X25519 static that Noise authenticated (HandshakeState.PeerStatic), never a
// value taken from an unauthenticated discovery hint.
func VerifyBinding(edPub ed25519.PublicKey, x25519Pub, sig []byte) bool {
	if len(edPub) != ed25519.PublicKeySize || len(x25519Pub) != nodeIDLen {
		return false
	}
	return ed25519.Verify(edPub, bindingMessage(x25519Pub), sig)
}

// persisted is the on-disk JSON form of an identity.
type persisted struct {
	Ed25519Seed   string `json:"ed25519_seed"`
	X25519Private string `json:"x25519_private"`
	Label         string `json:"label"`
}

const (
	dirPerm  os.FileMode = 0o700
	filePerm os.FileMode = 0o600
)

// Load reads an identity from path, or if it does not exist generates one,
// persists it atomically, and returns it. The returned bool reports whether a
// new identity was created.
func Load(path, label string) (*Identity, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		id, gerr := Generate(label)
		if gerr != nil {
			return nil, false, gerr
		}
		if serr := id.Save(path); serr != nil {
			return nil, false, serr
		}
		return id, true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("identity: read %s: %w", path, err)
	}
	id, derr := decode(data)
	if derr != nil {
		return nil, false, derr
	}
	return id, false, nil
}

// decode parses the persisted JSON form.
func decode(data []byte) (*Identity, error) {
	var p persisted
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("identity: parse: %w", err)
	}
	seed, err := base64.StdEncoding.DecodeString(p.Ed25519Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("identity: invalid ed25519 seed")
	}
	xpriv, err := base64.StdEncoding.DecodeString(p.X25519Private)
	if err != nil || len(xpriv) != nodeIDLen {
		return nil, errors.New("identity: invalid x25519 private key")
	}
	sk := ed25519.NewKeyFromSeed(seed)
	xpub, err := noise.DH25519.DH(xpriv, basepoint())
	if err != nil {
		return nil, fmt.Errorf("identity: derive x25519 public: %w", err)
	}
	return &Identity{
		Signing:     sk,
		NoiseStatic: noise.DHKey{Private: xpriv, Public: xpub},
		Label:       clampLabel(p.Label),
	}, nil
}

// basepoint returns the Curve25519 base point (u = 9), used to derive the
// X25519 public key from a stored private key.
func basepoint() []byte {
	b := make([]byte, nodeIDLen)
	b[0] = 9
	return b
}

// Save writes the identity to path atomically (temp file + rename) with 0700
// directory and 0600 file permissions.
func (id *Identity) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("identity: mkdir %s: %w", dir, err)
	}
	p := persisted{
		Ed25519Seed:   base64.StdEncoding.EncodeToString(id.Signing.Seed()),
		X25519Private: base64.StdEncoding.EncodeToString(id.NoiseStatic.Private),
		Label:         id.Label,
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("identity: marshal: %w", err)
	}
	return atomicWrite(path, data)
}

// atomicWrite writes data to a temp file in the same directory, then renames it
// over path so a crash never leaves a partial file.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("identity: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(filePerm); err != nil {
		tmp.Close()
		return fmt.Errorf("identity: chmod temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("identity: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("identity: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("identity: rename: %w", err)
	}
	return nil
}
