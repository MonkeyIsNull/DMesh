// Package discovery finds candidate peers on the local network. It sits behind
// the Discovery interface so the node's core logic never depends on real
// multicast: the production implementation uses mDNS/DNS-SD (mdns.go) and an
// in-process channel-based implementation (static.go) drives offline tests.
package discovery

import (
	"context"
	"net/netip"
)

// ServiceType is the DNS-SD service type DMesh advertises under.
const ServiceType = "_dmesh._udp"

// Domain is the mDNS domain (trailing dot per DNS-SD convention).
const Domain = "local."

// ProtoVersion is the current wire/discovery protocol version.
const ProtoVersion = 1

// PeerHint is an UNVERIFIED candidate learned from discovery.
//
// NodeID is a hint taken from an mDNS TXT record and is trivially spoofable on
// a LAN; it is NOT trusted until the Noise handshake authenticates the peer's
// static key and the identity binding re-derives the node ID. Trust and policy
// decisions must key off the authenticated identity, never this field.
type PeerHint struct {
	// NodeID is the advertised (unverified) node ID string.
	NodeID string
	// Label is the advertised human label.
	Label string
	// Addrs are candidate UDP endpoints to dial, in preference order.
	Addrs []netip.AddrPort
	// ProtoVersion is the advertised protocol version.
	ProtoVersion int
}

// Self describes this node for advertisement.
type Self struct {
	NodeID       string
	Label        string
	Port         int
	ProtoVersion int
}

// Discovery advertises this node and browses for peers.
type Discovery interface {
	// Advertise announces this node until ctx is canceled.
	Advertise(ctx context.Context, self Self) error
	// Browse returns a channel of peer hints that is closed when ctx is
	// canceled.
	Browse(ctx context.Context) (<-chan PeerHint, error)
	// Close releases discovery resources.
	Close() error
}
