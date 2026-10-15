package swim

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
)

// Incarnation persistence. The node's self incarnation is stored beside the
// Ed25519 identity in the config dir and resumed at persisted+1 on every start.
// This is the deterministic restart fix: because identity and incarnation live
// or die together, a node that holds its identity also holds an incarnation
// that strictly exceeds any stale Suspect/Dead/Left the mesh may still carry
// about it, so its post-restart Alive outruns that stale state everywhere,
// regardless of which peer reaped what. A wiped config dir means a genuinely
// new identity (a new node), not a restart.
//
// The file is 8 big-endian bytes written atomically (temp + rename) at 0600.

const incFilePerm = 0o600

// LoadIncarnation reads the persisted incarnation, returning 0 if the file is
// absent or unreadable (best-effort: a missing/corrupt file resumes from 0,
// which start-time +1 turns into incarnation 1).
func LoadIncarnation(path string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(data[:8])
}

// SaveIncarnation writes inc atomically to path.
func SaveIncarnation(path string, inc uint64) error {
	if path == "" {
		return errors.New("swim: empty incarnation path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], inc)
	tmp, err := os.CreateTemp(dir, ".inc-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(incFilePerm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(buf[:]); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
