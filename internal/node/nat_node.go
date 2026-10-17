package node

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
	"github.com/MonkeyIsNull/DMesh/internal/nat"
	"github.com/MonkeyIsNull/DMesh/internal/swim"
	"github.com/MonkeyIsNull/DMesh/internal/transport"
)

// nat_node.go holds the shared v0.4 NAT/relay state and helpers that are neither
// purely reflex (nat_loop.go) nor purely circuit control (relay_loop.go): the
// candidate store wire integration, the pseudo-address scheme, the off-loop
// relay forwarder, and the self-candidate maintenance. Every function here runs
// on the event loop (single writer) unless a doc note says otherwise.

const (
	// maxRelayChunk is the largest session DATA payload that still fits a single
	// datagram after being wrapped as a relay circData and re-sealed on the
	// carrier (see session/params.go for the 74-byte budget). The node clamps the
	// effective MaxChunk to this unconditionally.
	maxRelayChunk = 1110

	// candExtHeaderLen is the fixed extension header (marker + ver + count).
	candExtHeaderLen = 3
	// candExtSafety keeps a small margin under MaxPlaintext when appending the
	// candidate extension to a gossip frame.
	candExtSafety = 4

	// pseudoByte0 / pseudoByte1 are the fdme::/16 ULA prefix bytes that key a
	// relayed peer. A pseudo-address is a pure, structurally-undialable map key
	// (its low 14 bytes are a hash of relayNodeID||circuitID), never a dial
	// target.
	pseudoByte0 = 0xfd
	pseudoByte1 = 0x6d
)

// natInbound is a decrypted reflex (msgNat) body routed to the loop, tagged with
// whether it arrived on a direct UDP path (reflex is direct-only).
type natInbound struct {
	fromID     identity.NodeID
	fromAddr   netip.AddrPort
	fromDirect bool
	body       []byte
}

// circuitInbound is a decrypted circuit-control (msgRelay) body routed to the
// loop, tagged with the direct/relayed arrival path.
type circuitInbound struct {
	fromID     identity.NodeID
	fromAddr   netip.AddrPort
	fromDirect bool
	body       []byte
}

// fwdReq is one relay-forward job handed to the off-loop forwarder: the carrier
// (relay<->far-endpoint) session resolved ON the loop, the far endpoint's real
// address, and the already-wrapped msgRelay/circData plaintext to seal.
type fwdReq struct {
	carrier   *transport.Session
	relayAddr netip.AddrPort
	wrapped   []byte
}

// cryptoSeed draws a 64-bit seed from crypto/rand for the production circuit-id
// RNG, so circuit ids are unpredictable in production.
func cryptoSeed() int64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return int64(binary.LittleEndian.Uint64(b[:]))
}

// pseudoAddr builds the collision-free fdme::/16 pseudo-address for a relayed
// peer: prefix bytes + the first 14 bytes of SHA-256(relay||circuitID). It is
// unique per (relay, circuit) and canonAddr leaves IPv6 untouched, so it is
// stable as a map key. Port is a fixed non-zero marker value; it is never
// dialed.
func pseudoAddr(relay identity.NodeID, circuit nat.CircuitID) netip.AddrPort {
	var seed [40]byte
	copy(seed[:32], relay[:])
	binary.BigEndian.PutUint64(seed[32:], uint64(circuit))
	h := sha256.Sum256(seed[:])
	var a [16]byte
	a[0] = pseudoByte0
	a[1] = pseudoByte1
	copy(a[2:], h[:14])
	return netip.AddrPortFrom(netip.AddrFrom16(a), 1)
}

// isPseudoAddr reports whether addr is a relayed-peer pseudo-address (fdme::/16).
// It is used to keep a pseudo-address out of every dial/roster path.
func isPseudoAddr(addr netip.AddrPort) bool {
	a := addr.Addr()
	if !a.Is6() || a.Is4In6() {
		return false
	}
	b := a.As16()
	return b[0] == pseudoByte0 && b[1] == pseudoByte1
}

// --- self candidate maintenance --------------------------------------------

// initSelfCandidates seeds this node's signed candidate set from its host
// candidates and caps. Called once in New (no concurrency).
func (n *Node) initSelfCandidates() {
	n.selfCandGen = 1
	n.rebuildSelfCand()
}

// selfCaps returns this node's advertised capability bitset.
func (n *Node) selfCaps() nat.Caps {
	caps := nat.CapNat
	if n.relayRole {
		caps |= nat.CapRelay
	}
	return caps
}

// localHostCandidates returns the host candidates from the injected source (or
// the bound endpoint). The deterministic sim injects a fixed set so startup is
// reproducible.
func (n *Node) localHostCandidates() []nat.Candidate {
	var out []nat.Candidate
	if n.candidateSource != nil {
		for _, a := range n.candidateSource() {
			if a.IsValid() {
				out = append(out, nat.Candidate{Addr: canonAddr(a), Type: nat.CandHost})
			}
		}
		return out
	}
	if ep := n.selfEndpoint; ep.IsValid() {
		out = append(out, nat.Candidate{Addr: canonAddr(ep), Type: nat.CandHost})
	}
	return out
}

// rebuildSelfCand recomputes and signs the self candidate set from the host
// candidates plus every promoted (corroborated) reflexive address, at the
// current generation, and publishes it into the candidate store so it rides on
// gossip. The caller must hold n.mu (or be in New before Run).
func (n *Node) rebuildSelfCand() {
	cands := n.localHostCandidates()
	for ep := range n.reflexPromoted {
		cands = append(cands, nat.Candidate{Addr: ep, Type: nat.CandReflexive})
	}
	cands = nat.BoundSet(cands, n.natParams.MaxCandidatesPerMember)
	n.selfCand = nat.SignSelf(n.self, n.selfCandGen, n.selfCaps(), cands)
	cp := n.selfCand
	n.candStore[n.self.NodeID()] = &cp
}

// bumpSelfCand increments the generation and re-signs, used when the self set
// changes materially (a promoted reflexive candidate). The caller holds n.mu.
func (n *Node) bumpSelfCand() {
	n.selfCandGen++
	n.rebuildSelfCand()
}

// --- candidate gossip integration ------------------------------------------

// swimWithCands returns a gossip frame (msgSwim || payload) with the signed
// candidate extension appended for as many members as fit a live byte budget,
// dropping CANDIDATES first (never base updates) under pressure. payload is the
// swim.Encode output; carried names the members whose base updates ride in this
// frame (so a candidate rides only with a real member - orphan-drop on receive).
func (n *Node) swimWithCands(payload []byte, carried []swim.Update) []byte {
	frame := encodeSwim(payload)
	budget := transport.MaxPlaintext - len(frame) - candExtSafety
	if budget <= candExtHeaderLen {
		return frame
	}
	members := n.candidateMembersForFrame(budget, carried)
	if len(members) == 0 {
		return frame
	}
	ext := nat.EncodeCandExt(members, n.natParams.MaxCandidatesPerFrame)
	if len(frame)+len(ext) > transport.MaxPlaintext {
		return frame // fail closed: drop candidates, never base updates
	}
	return append(frame, ext...)
}

// candidateMembersForFrame selects self plus carried members with known
// candidate sets that fit the byte budget. Runs on the loop; reads loop-owned
// candStore/selfCand.
func (n *Node) candidateMembersForFrame(budget int, carried []swim.Update) []nat.CandMember {
	var out []nat.CandMember
	used := candExtHeaderLen
	add := func(subj identity.NodeID, set nat.CandSet) {
		if len(set.Sig) == 0 {
			return
		}
		m := nat.CandMember{Subject: subj, Set: set}
		ln := nat.EncodedCandMemberLen(m, n.natParams.MaxCandidatesPerFrame)
		if used+ln > budget {
			return
		}
		used += ln
		out = append(out, m)
	}
	self := n.self.NodeID()
	if len(n.selfCand.Sig) > 0 {
		add(self, n.selfCand)
	}
	seen := map[identity.NodeID]bool{self: true}
	for _, u := range carried {
		if seen[u.NodeID] {
			continue
		}
		seen[u.NodeID] = true
		if cs := n.candStore[u.NodeID]; cs != nil {
			add(u.NodeID, *cs)
		}
	}
	return out
}

// mergeCandExt parses the signed candidate extension trailing a gossip payload
// and merges each VERIFIED, admitted-member, strictly-newer set into the store.
// The caller holds n.mu. The merge is by independent generation (candGen), never
// the SWIM (incarnation,state) lattice, so it never touches the failure detector.
func (n *Node) mergeCandExt(body []byte, env swim.Envelope, now time.Time) {
	// Re-encode the decoded swim envelope to learn exactly where its payload ends
	// (swim.Decode ignores trailing bytes and reports no consumed length, and this
	// avoids any change to package swim). Encode is a pure inverse of Decode for a
	// valid frame, so the length matches the original payload.
	swimLen := len(swim.Encode(env))
	off, ok := nat.FindCandExt(body, swimLen)
	if !ok {
		return
	}
	members, ok := nat.DecodeCandExt(body[off:])
	if !ok {
		return // unknown marker/version/truncation: silent drop
	}
	self := n.self.NodeID()
	// Orphan-drop set: a candidate rides only with a real, allow-list-gated
	// member carried in the SAME envelope or already an admitted roster member.
	carried := make(map[identity.NodeID]bool, len(env.Updates))
	for _, u := range env.Updates {
		carried[u.NodeID] = true
	}
	for _, m := range members {
		if m.Subject == self {
			continue // never overwrite our own authoritative set from a relayer
		}
		if !n.rosterMemberLocked(m.Subject) && !carried[m.Subject] {
			continue // orphan: no real member to ride with
		}
		// Authenticated to the SUBJECT, not the relayer: a forged set fails here.
		if !nat.Verify(m.Subject, m.Set) {
			continue
		}
		if ex := n.candStore[m.Subject]; ex != nil && m.Set.Gen <= ex.Gen {
			continue // not strictly newer
		}
		cp := m.Set
		n.candStore[m.Subject] = &cp
	}
}

// rosterMemberLocked reports whether id is an admitted roster member (and, under
// enforcement, allow-listed). The caller holds n.mu.
func (n *Node) rosterMemberLocked(id identity.NodeID) bool {
	if _, ok := n.roster.State(id); ok {
		return true
	}
	return false
}

// --- off-loop relay forwarder ----------------------------------------------

// runForwarder drains fwd and performs the Seal+WriteTo for each relay-forward
// job off the loop, so the loop never seals a relay-forwarded DATA packet
// inline. Session.Seal is concurrency-safe, so sealing here alongside the loop's
// own seals on other sessions is sound.
func (n *Node) runForwarder(ctx context.Context) {
	defer n.wg.Done()
	for {
		select {
		case <-ctx.Done():
			// Drain outstanding units so the sim barrier stays balanced on
			// shutdown (mirrors readLoop's sbDone-on-cancel).
			for {
				select {
				case <-n.fwd:
					n.sbDone()
				default:
					return
				}
			}
		case req := <-n.fwd:
			n.doForward(req)
			n.sbDone()
		}
	}
}

func (n *Node) doForward(req fwdReq) {
	if req.carrier == nil {
		return
	}
	if len(req.wrapped) > transport.MaxPlaintext {
		return // runtime MTU guard
	}
	outer, err := req.carrier.Seal(req.wrapped)
	if err != nil {
		return
	}
	_ = n.packetConn().WriteTo(outer, req.relayAddr)
}

// enqueueForward hands a forward job to the off-loop forwarder, counting the
// cross-goroutine hand-off for the barrier. The loop resolved carrier/relayAddr.
// The send is non-blocking: if fwd is full (the forwarder's Seal+WriteTo cannot
// keep up with the far carrier), the job is dropped rather than blocking the
// single event loop - a slow carrier must never stall SWIM/session processing
// for every other peer on this relay. The relay stays a bounded, non-blocking
// dumb pipe; the endpoints retransmit the dropped inner frame.
func (n *Node) enqueueForward(ctx context.Context, req fwdReq) {
	n.sbAdd()
	select {
	case n.fwd <- req:
		n.relayFwd.Add(1)
	case <-ctx.Done():
		n.sbDone()
	default:
		n.sbDone() // fwd full: drop the forward, keep the loop live
	}
}

// --- test accessors (read loop-owned state under the renderer mutex) --------

// candidateSetForTest returns a copy of the verified candidate set held for id.
func (n *Node) candidateSetForTest(id identity.NodeID) (nat.CandSet, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	cs := n.candStore[id]
	if cs == nil {
		return nat.CandSet{}, false
	}
	return *cs, true
}

// selfCandGenForTest returns this node's current candidate generation.
func (n *Node) selfCandGenForTest() uint64 {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.selfCandGen
}

// peerPathKindForTest reports a peer's path kind (direct/relay) and whether a
// peer record exists for id.
func (n *Node) peerPathKindForTest(id identity.NodeID) (pathKind, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	p := n.byID[id]
	if p == nil {
		return pathDirect, false
	}
	return p.path.kind, true
}

// circuitCountForTest returns the number of live relayed peers keyed by circuit.
func (n *Node) circuitCountForTest() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.circuits)
}

// relayCircuitCountForTest returns the number of live circuits this node relays.
func (n *Node) relayCircuitCountForTest() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.circuitTbl.Len()
}

// relayForwardsForTest returns how many circuit frames this node has admitted to
// the forwarder (accepted past the byte buckets). Unlike the router's per-address
// attempt counter it is not polluted by direct-carrier SWIM/session traffic, so a
// test can measure exactly how much a flood was shed by the rate limits.
func (n *Node) relayForwardsForTest() uint64 {
	return n.relayFwd.Load()
}

// setReflexSpoofForTest forces this node's reflex responder to report ep as the
// observed address (modeling a malicious observer), set while quiesced.
func (n *Node) setReflexSpoofForTest(ep netip.AddrPort) {
	n.mu.Lock()
	n.reflexSpoof = ep
	n.mu.Unlock()
}

// hasReflexiveCandidateForTest reports whether id's stored set advertises a
// reflexive candidate equal to ep.
func (n *Node) hasReflexiveCandidateForTest(id identity.NodeID, ep netip.AddrPort) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	cs := n.candStore[id]
	if cs == nil {
		return false
	}
	for _, c := range cs.Cands {
		if c.Type == nat.CandReflexive && c.Addr == ep {
			return true
		}
	}
	return false
}
