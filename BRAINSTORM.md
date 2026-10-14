# DMesh — brainstorming

> **DMesh** ("dou mesh", the French pronunciation of *D*). A software mesh network.
> This is a living brainstorming doc — everything here is a *proposal to react to*, not a decision. Decisions get logged at the bottom as we make them.

---

## 0. One-liner (TBD)

*What is DMesh, in one sentence?* — to be nailed down once we pick a north star below.

Working draft: *"A small, self-hostable, encrypted peer-to-peer mesh that lets your devices talk to each other directly — no central server required — with a live view of the topology."*

---

## 1. North star — pick the kind of mesh

A "software mesh network" can mean several very different things. Which one is DMesh?

- **A) Private overlay network (VPN-style mesh)** — Tailscale / Nebula / ZeroTier territory. Devices anywhere form an encrypted virtual LAN; each node can reach every other as if on the same network. Usually a TUN device + virtual IPs, NAT traversal, direct-when-possible / relay-when-not.
  - *Great if the goal is "connect all my machines/servers/phones securely."*
- **B) Decentralized data / gossip mesh** — nodes gossip membership + messages; pub/sub or a replicated key-value store; eventually consistent; survives heavy churn. (libp2p / SWIM + gossip vibes.)
  - *Great if the goal is "distribute state/messages across many nodes resiliently."*
- **C) Local-first / infrastructure-less mesh** — nodes discover and route to each other on a LAN (or local radio) with **no internet and no server**; keeps working when the ISP is down.
  - *Great if the goal is "resilient local comms that don't depend on anyone's cloud."*
- **D) From-scratch systems project** — implement membership + routing + encrypted transport ourselves to learn/own the stack (any of A–C as the shape, but the point is building it, not reusing libp2p/WireGuard wholesale).

**My lean:** **A with a strong serverless twist + B's gossip for membership.** i.e. a WireGuard/Nebula-style encrypted overlay, but **no central coordinator** — peers find each other via local discovery + a gossip membership protocol, so there's nothing to host. That's the gap most of the popular tools leave (Tailscale/Nebula both need a control plane/lighthouse).

---

## 2. Core subsystems (every mesh needs these)

1. **Node identity** — each node = a keypair; node ID = public key (Ed25519). Human label optional.
2. **Discovery / membership** — how nodes find each other and track who's up:
   - local: **mDNS** on the LAN (we just spent a week in this world 😄)
   - bootstrap: a seed peer / rendezvous address
   - decentralized: a **DHT** and/or a **gossip membership protocol (SWIM)** with failure detection
3. **Transport** — **UDP** base; **encrypted** with the **Noise protocol** (don't roll our own crypto); **NAT traversal** (STUN + UDP hole-punching, relay fallback). QUIC is an option.
4. **Routing** — getting A→B when not directly connected: full-mesh direct first, **relay through a peer** when hole-punching fails; later, a real routing table (link-state/distance-vector) for multi-hop.
5. **Addressing / data plane** — two flavors:
   - **OS-level:** a **TUN** device + virtual IPs → acts like a real NIC, any app "just works" (the VPN model).
   - **App-level:** a library/daemon apps talk to (send messages / pub-sub), no OS integration. Simpler, no root.
6. **Security** — end-to-end encryption, mutual auth from node keys, a trust model (pre-shared network key? signed membership? an allow-list?).
7. **Observability (our signature move)** — a **live dashboard of the mesh**: topology graph, per-link health/latency, who's relaying for whom, churn. Given netdebug/PacketVelocity, this is very on-brand and a real differentiator.

---

## 3. Design axes (the forks to decide)

| Axis | Options | Starting lean |
|---|---|---|
| Control plane | central coordinator ↔ **fully serverless/P2P** | serverless |
| Data plane | **OS-level TUN + virtual IPs** ↔ app-level messaging library | TBD — depends on north star |
| Transport crypto | **Noise/WireGuard-style** ↔ TLS ↔ roll-our-own(no) | Noise |
| NAT traversal | direct-only ↔ **hole-punch + relay fallback** | hole-punch + relay |
| Routing | direct full-mesh ↔ **+ relay** ↔ + multi-hop routing | start direct+relay |
| Language | **Go** ↔ Rust ↔ C | Go (see §5) |
| Scope v0.1 | tiny (2 nodes, direct, encrypted) → grow | start tiny |

---

## 4. Candidate v0.1 (smallest thing that's real)

A deliberately tiny first milestone to get something working end-to-end:

- Two (then N) nodes, each with an Ed25519 identity.
- **mDNS discovery on the LAN** → peers find each other with zero config.
- **Noise-encrypted UDP** channel between peers.
- Send bytes/messages peer-to-peer (app-level first; TUN later).
- A one-command demo: `dmesh up` on two machines on the same wifi → they see each other and can exchange a message.
- A tiny status view (CLI or a localhost page) showing known peers + link state.

Then grow: NAT traversal → relay → virtual IPs/TUN → gossip membership → the topology dashboard.

---

## 5. Language note

Mesh networking is Go's home turf — Tailscale, Nebula, and most of this ecosystem are Go (net stack, goroutines for many concurrent peers, solid crypto libs, `wireguard-go`, easy cross-compile). Rust is the other strong choice (perf + safety). C is doable but fights you on concurrency/crypto/NAT. Given the amount of networking + concurrency + crypto here, **Go is the pragmatic pick** — but worth a deliberate call since the recent projects have been C.

---

## 6. Open questions (for Adam)

1. **North star** — which of A/B/C/D (or a blend) is DMesh really for? What do *you* want to use it for?
2. **OS-level vs app-level** — a real virtual-network/VPN feel (TUN, root), or a library/daemon apps send messages through (no root)?
3. **Serverless or OK with a small coordinator?** (Serverless is harder but more distinctive.)
4. **Language** — Go (my lean), Rust, or stick with C?
5. **The signature** — is the live mesh-topology dashboard a core feature from day one (ties into netdebug/PV), or a later nicety?

---

## 7. Refined north star (working)

**DMesh = a resilient, serverless overlay mesh with durable, resumable sessions.**
B (gossip membership/state) + C (local-first, no infra) + "reachable anywhere, can't be knocked out" ⇒ a hardened, serverless A. The three were never competing — they're layers of one thing.

## 8. Core principles (the Mosh insight)

1. **Identity, not address.** A node *is* its keypair; node ID = pubkey. Peers, routes, and sessions are keyed by node ID. IP:port is a disposable, roamable *hint*. A node that changes networks and comes back is the *same* node, recognized by its key.
2. **Sync state, not a connection.** The transport (UDP datagrams) is disposable; the *session state* is the truth. Membership + shared state are gossiped and replicated; a node that leaves is marked unreachable but **never forgotten**, and reconciles on return. CRDTs so partitioned nodes merge cleanly on heal.

## 9. The data plane — "what rides on the mesh" (clarifying Q1)

The question is really *at what level* DMesh hands connectivity to apps:
- **(a) Raw virtual network** (VPN / TUN device + virtual IPs): tunnels opaque IP packets; every existing app "just works." *Tailscale model.*
- **(b) Resumable session/stream channel** (an API): apps "open a durable stream to node X"; DMesh owns the channel, so it can resume it. ← **this is what Adam described in Q2.**
- **(c) Built-in services on top:** pub/sub, a replicated KV store, RPC.

**Lean:** (b) as the core primitive (a resumable, identity-anchored stream), with (a) as a later mode and (c) as optional sugar.

## 10. Durable / resumable sessions — THE signature feature (answering Q2's "how")

Goal: a node drops, returns, and *continues where it left off* — pull the rest of a query, still be in vim. Four parts:
1. **Identity-anchored sessions.** A session = `(peerNodeID, sessionID)`, authenticated by keys — not an IP:port or TCP connection. So a returning node can *re-attach*.
2. **Keep the session alive across drops.** The far side treats a transport drop as *paused* (grace timer), not *ended* — it does NOT tear down the running task/stream. Re-attach within the window resumes it.
3. **Acked, offset/sequence-based, resumable delivery.** Data is chunked + sequence-numbered; the receiver acks "I have up to N"; the sender buffers unacked data. After drop+reconnect both sides exchange "where were we?" and the sender resumes at N+1. ("Pull the rest of the DB query" = resume from the last acked row/offset.) Same idea as QUIC stream migration and resumable uploads (tus / S3 multipart).
4. **State sync on re-attach.** Send only the delta since the node was last caught up (Mosh syncs the screen diff; we sync the stream cursor, or app state via CRDT).

Two flavors, different reach:
- **Resumable transfer** (the DB case): DMesh owns the buffer + cursor → fully in our control, very doable.
- **Re-attach to a live session** (the vim case): the *application* must keep running on the far side. DMesh provides the plumbing (keep-alive + re-attach + state sync); "vim still running" means it ran inside a DMesh **session host** (like `mosh-server`/`tmux`) that kept it alive. So DMesh = the durable-session *substrate*; a full Mosh-like app runs *over* it.

> **The real differentiator:** Tailscale/Nebula give you connectivity, but your SSH/TCP on top still dies on a drop. DMesh makes **resumable sessions a first-class mesh primitive** — *"a mesh where your sessions survive."*

## 11. Security & DoS resistance (answering Q3 — honestly)

The serverless + identity-based design already buys most of it:
- **No central server** = the #1 DoS target in centralized systems is simply gone.
- **Authenticated + encrypted (Noise) everything** = off-path injection/spoofing and unsolicited junk are dropped *cheaply*, before any work.

Add the proven defenses:
- **WireGuard-style cookie handshake** — no state allocated for an unproven initiator → handshake-flood resistant.
- **No amplification** in protocol design (a small request can't elicit a big response) → useless for reflection attacks.
- **Permissioned membership** (signed invites / shared network key / a tiny CA) → **Sybil & eclipse largely neutralized**; only credentialed nodes join. Right call for a personal/trust-group mesh. (Open, anyone-can-join membership needs proof-of-work/social-graph trust — research territory, out of scope for v1.)
- **Per-peer rate limits + backpressure.**
- **Honest limit:** raw volumetric flooding of a node's *uplink* can't be solved at the host — that needs upstream scrubbing, and nobody (incl. Tailscale) solves it locally. We just make sure we're never an amplifier and that junk is cheap to drop.

## 12. Decisions log

- **D1 — North star:** resilient, serverless overlay with durable/resumable sessions (B+C synthesis; a hardened serverless A). *[Adam, 2026-10-14]*
- **D2 — Core principles:** identity-not-address; sync-state-not-connection. *[2026-10-14]*
- **D3 — Signature feature:** Mosh-style durable/resumable sessions as a first-class primitive. *[leaning]*
- **D4 — Membership:** permissioned (signed invite / shared trust). ✅ *[Adam, 2026-10-14]*
- **D5 — Language:** Go. ✅ *[Adam, 2026-10-14]*
- **D6 — Positioning:** "a serverless mesh where your sessions don't die" (see §13). *[leaning]*
- **Open:** data-plane level (a/b/c — leaning b), rendezvous mechanism specifics.

## 13. Differentiation — why DMesh exists (not "a worse Tailscale")

**The landscape (honest):**
- **Control-plane meshes** (Tailscale, Nebula, ZeroTier, Netmaker, Innernet): easy + polished, but all depend on a coordination service / lighthouses / controllers you host or trust. Great *connectivity* — but the sessions on top (SSH/TCP/DB) still die on any network blip.
- **Serverless / decentralized** (Yggdrasil, libp2p): no central anything — but they're about *routing/connectivity* (and are more experimental/complex), not durable sessions.
- **Mosh:** resumable sessions — but point-to-point, shell-only, not a mesh.

**Nobody combines serverless + durable sessions. That's the lane.**

**Differentiators (ranked):**
1. **Sessions survive. (Hero.)** The first mesh where a *session itself* resumes across roams/drops/reconnects — Mosh's resilience generalized to a whole mesh and any session, not just a shell. Tailscale reconnects you; your SSH is still dead. DMesh keeps the session.
2. **Truly serverless.** No control plane, no lighthouse, no controller, nobody in the path deciding if you may connect. Nothing to host, nothing to take down. (Tailscale structurally can't — it's their model/business.)
3. **A mesh you can see.** A local, self-contained, live topology + health + session dashboard (netdebug/PacketVelocity lineage). Most mesh tools are opaque or SaaS-dashboard'd; DMesh shows you the whole thing per node, no cloud.
4. **Local-first / infra-independent.** Keeps working on a LAN with no internet and no coordinator. (Ties to the "kicked off my wifi" origin.)

**Positioning line:** *"A serverless mesh where your sessions don't die."* Tailscale keeps your devices connected; DMesh keeps your devices connected **and your work alive**, with no one in the middle.

**Killer scenario:** flaky connection (train / café, bouncing wifi↔cellular — the exact kicked-off-wifi pain). Mid-transfer of a big dataset / a long remote task / an interactive session. On Tailscale: every blip kills it, you restart. On DMesh: blip → roam → return → it resumes mid-stream, you never lost your place, and no server was in the path.

**Honest tradeoffs (eyes open):**
- Serverless makes cross-NAT rendezvous genuinely harder — a control plane is partly *why* Tailscale's NAT traversal is so reliable. We take on real distributed-systems work (gossip, rendezvous, consistency) to avoid the server. That cost *is* part of the project's point.
- Durable sessions aren't transparent to every existing app the way a TUN VPN is: apps either use DMesh's session API or run in a session-host (the tmux/mosh-server relationship). We can still offer a plain TUN connectivity mode; sessions are the opt-in superpower.
