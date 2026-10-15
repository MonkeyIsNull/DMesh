package transport

import (
	"testing"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
)

func TestValidatePSKFailClosed(t *testing.T) {
	if err := ValidatePSK(nil); err != ErrNoNetworkKey {
		t.Fatalf("nil key: err = %v, want ErrNoNetworkKey", err)
	}
	if err := ValidatePSK([]byte{}); err != ErrNoNetworkKey {
		t.Fatalf("empty key: err = %v, want ErrNoNetworkKey", err)
	}
	if err := ValidatePSK(make([]byte, 16)); err == nil {
		t.Fatal("16-byte key accepted")
	}
	if err := ValidatePSK(make([]byte, 32)); err != nil {
		t.Fatalf("valid 32-byte key rejected: %v", err)
	}
}

func TestAllowListTOFU(t *testing.T) {
	a := genID(t).NodeID()
	// Empty allow-list, not trust-only => trust-on-first-use accepts anyone.
	p := AllowList(nil, false)
	if p(a) != TrustAccept {
		t.Fatal("TOFU rejected a PSK-valid peer")
	}
	// Empty allow-list with trust-only => reject everyone.
	p = AllowList(nil, true)
	if p(a) != TrustReject {
		t.Fatal("trust-only accepted an unlisted peer")
	}
}

func TestAllowListEnforced(t *testing.T) {
	trusted := genID(t).NodeID()
	stranger := genID(t).NodeID()
	set := map[identity.NodeID]struct{}{trusted: {}}

	p := AllowList(set, false)
	if p(trusted) != TrustAccept {
		t.Fatal("listed peer rejected")
	}
	if p(stranger) != TrustReject {
		t.Fatal("unlisted peer accepted when allow-list is non-empty")
	}
}
