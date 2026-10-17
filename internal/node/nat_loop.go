package node

import (
	"context"
	"net/netip"
	"sort"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/nat"
	"github.com/MonkeyIsNull/DMesh/internal/swim"
)

// nat_loop.go is Phase 0: serverless reflexive discovery on the direct path. A
// node asks a couple of CapNat peers "what source address do you see for me?";
// the peer answers with the NAT-translated source it observed (the serverless
// STUN trick). An observation is kept internal until MinReflexObservers
// independent observers report the SAME ip:port, defeating a lone spoofed
// reflexResp (which, additionally, never causes a packet to be emitted toward
// the claimed address). All work is on the event loop; runNatProbe only signals.

// runNatProbe fires reflex probes on the injectable clock. It is structured
// exactly like runPhases and only signals the loop; all NAT work happens on the
// loop. It never touches the peer table.
func (n *Node) runNatProbe(ctx context.Context) {
	defer n.wg.Done()
	t := n.clk.NewTimer(n.natParams.ReflexInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C():
			n.sbAdd()
			select {
			case n.natProbe <- struct{}{}:
			case <-ctx.Done():
				n.sbDone()
				return
			}
			t.Reset(n.natParams.ReflexInterval)
		}
	}
}

// InjectNatProbe delivers one reflex probe to the loop, used by the deterministic
// harness in place of the probe-timer goroutine (mirrors InjectPhase). The probe
// is counted so settle() blocks until the loop has fully processed it.
func (n *Node) InjectNatProbe(ctx context.Context) {
	n.sbAdd()
	select {
	case n.natProbe <- struct{}{}:
	case <-ctx.Done():
		n.sbDone()
	}
}

// handleNatProbe sends a reflexReq to up to ReflexMaxPeers connected, direct,
// CapNat peers, chosen in a deterministic node-ID order (map iteration order is
// otherwise randomized, which would perturb the reflex sequence).
func (n *Node) handleNatProbe() {
	n.mu.Lock()
	var cands []*peer
	for id, p := range n.byID {
		if p.state != StateConnected || p.sess == nil {
			continue
		}
		if p.path.kind != pathDirect {
			continue // reflex is direct-only at both ends
		}
		cs := n.candStore[id]
		if cs == nil || cs.Caps&nat.CapNat == 0 {
			continue // only ask peers that advertised NAT participation
		}
		cands = append(cands, p)
	}
	n.mu.Unlock()
	sortPeersByID(cands)
	if len(cands) > n.natParams.ReflexMaxPeers {
		cands = cands[:n.natParams.ReflexMaxPeers]
	}
	for _, p := range cands {
		n.sealSend(p, p.sess, encodeNat(nat.EncodeReflexReq()))
	}
}

// handleNatIn processes one reflex message from an authenticated peer.
func (n *Node) handleNatIn(in natInbound) {
	m, ok := nat.DecodeReflex(in.body)
	if !ok {
		return // unknown version/sub/truncation: silent drop
	}
	now := n.clk.Now()
	switch m.Sub {
	case nat.ReflexReq:
		n.handleReflexReq(in, now)
	case nat.ReflexResp:
		n.handleReflexResp(in, m.Observed, now)
	}
}

// handleReflexReq answers a direct reflexReq with the NAT-translated source we
// observed, rate-limited per source. A relayed reflexReq is ignored (a synthetic
// address never crossed a NAT, so it is meaningless as a reflexive candidate).
func (n *Node) handleReflexReq(in natInbound, now time.Time) {
	if !in.fromDirect {
		return
	}
	if !in.fromAddr.IsValid() || isPseudoAddr(in.fromAddr) {
		return
	}
	// Per-source responder rate limit (security-low responder DoS).
	if r := n.natParams.ReflexRespRatePerSource; r > 0 {
		minGap := time.Duration(float64(time.Second) / r)
		if last, ok := n.reflexRespAt[in.fromID]; ok && now.Sub(last) < minGap {
			return
		}
	}
	n.reflexRespAt[in.fromID] = now

	n.mu.RLock()
	p := n.byID[in.fromID]
	var sendP *peer
	if p != nil && p.sess != nil && p.path.kind == pathDirect {
		sendP = p
	}
	observed := in.fromAddr
	if n.reflexSpoof.IsValid() {
		observed = n.reflexSpoof // test-only malicious responder
	}
	n.mu.RUnlock()
	if sendP != nil {
		n.sealSend(sendP, sendP.sess, encodeNat(nat.EncodeReflexResp(observed)))
	}
}

// handleReflexResp records a per-observer reflexive observation and promotes it
// to a dialable/gossipable candidate only on MinReflexObservers corroboration.
// A response carrying an fdme:: address is rejected (it never crossed a NAT).
func (n *Node) handleReflexResp(in natInbound, observed netip.AddrPort, now time.Time) {
	if !in.fromDirect {
		return
	}
	if !observed.IsValid() || isPseudoAddr(observed) {
		return
	}
	n.mu.Lock()
	n.reflexObs[in.fromID] = observed
	count := 0
	for _, ep := range n.reflexObs {
		if ep == observed {
			count++
		}
	}
	// Residual threat, by design at this corroboration threshold: MinReflexObservers
	// independent observers reporting the SAME ip:port promote it into our signed,
	// advertised candidate set. A LONE spoofed observation is defended (count stays
	// 1, and this handler never emits a packet toward the claimed address). But
	// MinReflexObservers or more COLLUDING credentialed observers can agree on an
	// attacker-chosen ip:port and promote it, aiming honest peers' re-dial handshake
	// traffic at that address (a small reflection primitive). MinReflexObservers is
	// the knob here. The real fix - signed per-observer observations (and/or a higher
	// threshold) so a reflexive address carries proof of who observed it - is
	// deferred; see the v0.4 security-scope note in README.md.
	promote := count >= n.natParams.MinReflexObservers && !n.reflexPromoted[observed]
	if promote {
		n.reflexPromoted[observed] = true
		n.bumpSelfCand()
	}
	n.mu.Unlock()

	if promote {
		n.regossipSelfCand()
	}
}

// regossipSelfCand pushes our (possibly newly-bumped) candidate set to every
// connected direct peer via a lightweight SWIM sync carrying our self-Alive, with
// the candidate extension appended. Runs on the loop.
func (n *Node) regossipSelfCand() {
	n.mu.Lock()
	selfAlive := n.roster.SelfAlive()
	var conns []*peer
	for _, p := range n.byID {
		if p.state == StateConnected && p.sess != nil && p.path.kind == pathDirect {
			conns = append(conns, p)
		}
	}
	n.mu.Unlock()
	sortPeersByID(conns)
	for _, p := range conns {
		env := swim.Envelope{Kind: swim.KindSync, Seq: n.nextSeq(), Updates: []swim.Update{selfAlive}}
		n.sealSend(p, p.sess, n.swimWithCands(swim.Encode(env), []swim.Update{selfAlive}))
	}
}

// sortPeersByID orders peers by node-ID string for deterministic send order.
func sortPeersByID(ps []*peer) {
	sort.Slice(ps, func(i, j int) bool {
		return ps[i].nodeID.String() < ps[j].nodeID.String()
	})
}
