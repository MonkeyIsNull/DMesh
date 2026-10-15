# DMesh

[![CI](https://github.com/MonkeyIsNull/DMesh/actions/workflows/ci.yml/badge.svg)](https://github.com/MonkeyIsNull/DMesh/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/MonkeyIsNull/DMesh)](https://github.com/MonkeyIsNull/DMesh/releases/latest)
![Go version](https://img.shields.io/github/go-mod/go-version/MonkeyIsNull/DMesh)
![platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)
![serverless](https://img.shields.io/badge/serverless-yes-brightgreen)
![status](https://img.shields.io/badge/status-pre--alpha-orange)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**A serverless mesh where your sessions don't die.**

DMesh (*"dou mesh"* — the French pronunciation of *D*) is a resilient, serverless peer-to-peer overlay mesh written in Go. Nodes find each other and connect directly — with **no central coordination server, nothing to host, and nothing to knock out** — and, unlike other meshes, the **sessions themselves survive** roaming, drops, and reconnects (Mosh's resilience, generalized to a whole mesh).

> ⚠️ **Status: pre-alpha.** v0.1 shipped the foundation (credentialed mDNS discovery + an encrypted, mutually-authenticated Noise transport). **v0.2 added SWIM gossip membership + failure detection**: the mesh maintains a *replicated, gossiped roster* of who is a member and their liveness (alive / suspect / dead / left), detects failures with no coordinator, and learns peers transitively via gossip beyond direct mDNS. **v0.3 ships the hero feature — durable / resumable sessions**: a reliable, ordered byte-stream anchored to peer *identity* rather than network endpoint, so a transfer pauses on a mid-stream drop and resumes byte-exact after the link heals or the node roams from one network to another (wifi to cellular), with no bytes lost, duplicated, or reordered. The remaining hero features — NAT traversal/relay, the topology dashboard, virtual-interface (TUN) mode — are later milestones.

## Why DMesh?

- **Sessions survive.** Mid-transfer or in a long remote session, your network blips or you roam from wifi to cellular — DMesh resumes where you left off instead of starting over.
- **Truly serverless.** No control plane, no lighthouse, no controller — no one in the path deciding whether you may connect, and nothing to take down.
- **A mesh you can see.** A local, self-contained live view of the topology, link health, and sessions — no cloud.
- **Local-first.** Keeps working on a LAN with no internet and no coordinator.

## How it compares

| | control plane | sessions survive drops | serverless |
|---|:---:|:---:|:---:|
| Tailscale / Nebula / ZeroTier | yes (server / lighthouse) | no | no |
| Yggdrasil / libp2p | no | no | yes |
| Mosh | — (point-to-point) | yes (one shell) | — |
| **DMesh** | **none** | **yes (any session, whole mesh)** | **yes** |

## What v0.1 actually does

- **Identity** — each node is an Ed25519 keypair; the node ID is its public key, shown as lowercase base32 (`DW2ZI4NFCA…`). Generated on first run and persisted to the OS config dir (`~/Library/Application Support/dmesh` on macOS, `$XDG_CONFIG_HOME/dmesh` or `~/.config/dmesh` on Linux). A separate X25519 static is the Noise DH key, **bound** to the identity by a signature carried inside the handshake (no Ed25519→X25519 key conversion).
- **Discovery** — zero-config mDNS/DNS-SD on the LAN (`_dmesh._udp`), behind an interface so the core is testable without multicast.
- **Transport** — UDP carrying a `Noise_XXpsk0_25519_ChaChaPoly_BLAKE2s` handshake (via the vetted [`flynn/noise`](https://github.com/flynn/noise)), made reliable over UDP with stop-and-wait retransmit, then AEAD data frames with an explicit nonce and a replay window. **XX** is used because discovery hints are unauthenticated and LAN-spoofable, so each side must learn and verify the peer's static key in-band.
- **Permissioned membership (fail-closed)** — a mandatory 32-byte **pre-shared network key** is mixed as the Noise PSK (`psk0`): a wrong or absent key fails the handshake at message 1. There is **no keyless fallback** — `dmesh up` refuses to start without a key. An optional **allow-list** of trusted node IDs is checked *after* the handshake, against the cryptographically-authenticated identity (never the spoofable mDNS TXT record).

> **Honest scope of "permissioned":** with an empty allow-list, v0.1 is **trust-on-first-use** — anyone holding the network key is admitted (the intended shared-secret model). Per-node control exists only when you populate the allow-list (or pass `--trust-only`). Full signed invites / a tiny CA are a later milestone.

## What v0.2 adds — SWIM membership

- **A replicated roster, not just a peer list.** Each node keeps a membership table keyed by node ID with a state (`alive` / `suspect` / `dead` / `left`), a monotonic **incarnation**, an endpoint hint, and a last-change time. A node that leaves or fails is **marked, not forgotten** — dead/left entries are retained a while (then reaped behind a bounded tombstone) so a return reconciles. `dmesh up` now shows this **full gossiped roster**, including peers it learned only via gossip and never discovered directly.
- **Coordinator-free failure detection (SWIM + Lifeguard).** Each 1s protocol period a node direct-pings one target (round-robin over a shuffled member list); on no ack within `T/3` it asks `K=3` random members to **indirect-ping** (ping-req) it; still no ack by period end marks it **suspect**. A suspect becomes **dead** after a log-scaled suspicion timeout unless it refutes.
- **Incarnation numbers + refutation.** Membership facts are a total-order lattice over `(incarnation, state-precedence)` — higher incarnation wins; at a tie, `left > dead > suspect > alive`. A node **refutes** a suspicion about itself by bumping its incarnation and broadcasting `alive`. The self-incarnation is **persisted beside the identity** and resumed at `persisted+1`, so a **restarted** node (even one a peer already reaped) deterministically out-runs any stale state about it.
- **Bounded, infection-style gossip.** Membership updates piggyback on ping/ack/ping-req frames (no standalone gossip packets in steady state), each retransmitted ~`O(log N)` times then retired, capped per datagram to stay under the UDP MTU. A completed handshake triggers a bounded bidirectional **join-sync** that both seeds a new node and lets a stale node learn it must refute — this is the connectivity-triggered reconciliation that stands in for periodic anti-entropy.
- **Runs over the existing Noise transport.** SWIM messages are a small, versioned, length-checked format carried inside the v0.1 AEAD data frames (app type `0x10`), so **all membership traffic rides the authenticated, permissioned channels** — only credentialed peers gossip.

```sh
dmesh members          # run briefly, print the gossiped roster once, exit
dmesh up               # the live status view now shows the full roster
# Ctrl-C / SIGTERM announces a graceful "left" to peers before exiting
```

> **"Alive" for a peer you can't reach.** Gossip may tell node A about peer C that A cannot directly reach (NAT / off-LAN). A **never probes, and therefore never suspects, a member it has no live session to** — its view of C is purely gossip-driven, kept alive as long as *some* member can reach C. A suspicion is cleared only by C's own higher-incarnation refutation carried back over a connected path, never by "someone says C is alive." Actual off-LAN *data* reachability (hole-punching / relay) is the next milestone; v0.2 only guarantees C is not falsely declared dead while others can reach it.

### Security scope of v0.2 membership (read this)

v0.2 defends failure detection and *transient* suspicion of **honest** members inside a credentialed mesh: gossip is bounded (no amplification), indirect probing is identity-only (no reflection / dial-storm), and self-incarnation inflation is capped (`Suspect{self, HUGE}` is provably forged and dropped, since only a node advances its own incarnation).

v0.2 does **not** defend against a credentialed-but-**malicious** member forging membership. Because an update carries `(nodeID, incarnation, state)` with **no per-field authorship binding**, any credentialed member can author any fact about any node — win an incarnation war against a victim at every node that has no direct session to it, keep a dead node "alive", or inject a fabricated member (bounded by the allow-list when enforced). The real fix — **per-update Ed25519 signatures over `(nodeID, incarnation, epoch, state)`** so only a node authors its own state — is deferred to the signed-invite / CA milestone (the `epoch` byte is already reserved on the wire). The present-day mitigations are the allow-list (bounds *who* can inject) and handshake-as-ground-truth (protects a victim's directly-connected neighborhood). Note the transport replay window does **not** stop membership replay — incarnation monotonicity (the lattice + tombstones) is the sole membership anti-replay.

## What v0.3 adds — durable sessions

- **A reliable stream over best-effort datagrams.** The session layer lays a reliable, ordered, flow-controlled byte-stream over the best-effort encrypted Noise datagrams: cumulative ACK, Karn/Jacobson RTO estimation, out-of-order reassembly, and fixed send/receive windows. Each DATA frame is one datagram with no fragmentation — `MaxChunk` is 1156 bytes (the transport's max plaintext minus the session+data header).
- **Keyed by identity, not endpoint — so sessions survive a roam.** A session is anchored to the peer's *authenticated identity*, never to a network address. A mid-stream drop **pauses** the stream rather than failing it — the pause is stall-driven, because a silent blackhole produces no close to react to — and when connectivity returns the stream **resumes byte-exact** from the cumulative-acked offset. A link blip that heals on the surviving Noise epoch recovers by plain same-epoch RTO retransmit; a roam to a different endpoint/network re-handshakes onto a **new epoch** and reconciles with a RESUME exchange. Either way no bytes are lost, duplicated, or reordered.
- **Graceful half-close with a bounded TIME-WAIT.** Each direction half-closes with a FIN; once both directions are drained the session enters a short, bounded TIME-WAIT (a dedicated `Linger`, default 5s, clamped to `Grace`) that frees the send/receive buffers immediately and releases the session slot after the linger. Completed transfers therefore do not leak against the bounded session caps (`MaxTotalSessions` / `MaxSessionsPerPeer`).
- **Bounded memory + roster-driven teardown.** The send buffer is capped by the send window and the receive buffer by the receive window plus an out-of-order segment cap, all freed on close or teardown. A paused session is torn down early (`ErrPeerGone`) the moment SWIM marks the peer `dead`/`left`, and an unrecovered pause expires on the grace timeout (`ErrGraceTimeout`) rather than lingering forever.
- **Identity-guarded.** A frame is applied to a session only if it arrived on a transport authenticated as that session's peer, checked before any state mutation — so a third credentialed member cannot hijack or reset someone else's session.
- **Runs over the existing Noise transport.** Session sub-frames are carried inside the v0.1 AEAD data frames under app type `0x20` (SWIM is `0x10`), so **all session traffic rides the authenticated, permissioned channels** — only credentialed peers can open or feed a session.

```sh
# receiver: accept one inbound session and write the file into DIR
dmesh recv --out ./downloads

# sender: open a durable session to a node ID and stream a file over it
dmesh send <node-id> ./bigfile.iso

# force a mid-stream pause/resume on a single machine (rebinds the local socket
# to a fresh endpoint, exercising the real roam/resume path)
dmesh send <node-id> ./bigfile.iso --chaos
```

Both ends print the SHA-256 of the bytes they moved on completion, so a human can
confirm the transfer is identical across the pause/resume. `send` and `recv` share
the usual node flags (`--label`, `--port`, `--no-mdns`).

> **Honest scope of "resume":** resume is bounded by a session's lifetime, not
> unlimited. A pause is retained only for `Grace` (default 30s) awaiting re-attach;
> past that it is torn down with `ErrGraceTimeout`, and a SWIM `dead`/`left` tears a
> paused session down sooner (`ErrPeerGone`). Off-LAN reconnection still depends on
> reaching the peer's endpoint — NAT traversal / relay is the next milestone — so
> today's resume covers link blips and roaming between reachable networks. The stream
> ships correct reliability + flow control with a fixed send window and RTO-only loss
> recovery; congestion control and SACK are deferred throughput refinements.

## Build

```sh
go build ./...
go test ./...          # offline, deterministic (loopback UDP + injected discovery)
go test -race ./...
```

Requires Go 1.26+ (tracks the `golang.org/x/crypto` floor).

## Usage

```sh
# print (and on first run, generate) this node's identity
dmesh id --label laptop

# create a network key and share it out-of-band with your peers
dmesh network-key gen            # prints a base64 key; stored at 0600
dmesh network-key show           # prints only a short fingerprint, never the secret

# on each peer, install the SAME key, then bring the node up
dmesh network-key set <base64-key>
dmesh up --label laptop          # discover, connect, and show a live status view

# optional: restrict membership to specific nodes (authenticated IDs)
dmesh trust <node-id> alice
dmesh trust list
dmesh up --trust-only            # admit only allow-listed peers
```

`dmesh up` prints a live status view: this node's ID/label/endpoint and network-key
fingerprint, then the **full gossiped membership roster** (ID, label, state, incarnation,
endpoint hint, direct-link status, last change) — including members learned only via
gossip. `dmesh members` prints that roster once and exits.

> **macOS note:** the first LAN run may raise a *Local Network* permission prompt for
> mDNS. CI and the offline test suite never touch multicast; the real-mDNS path is
> only exercised under `DMESH_MDNS_E2E=1`.

## Roadmap

Done: gossip membership (SWIM, v0.2); **durable/resumable sessions** (the hero feature, v0.3). Later milestones, in order: NAT traversal / relay (off-LAN data reachability) → topology dashboard → virtual-interface (TUN) mode. Membership hardening — per-update signatures (forged-membership defense), signed invites / a tiny CA (Sybil/eclipse) — rides the signed-invite milestone.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Adam Guyot.
