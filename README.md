# DMesh

[![CI](https://github.com/MonkeyIsNull/DMesh/actions/workflows/ci.yml/badge.svg)](https://github.com/MonkeyIsNull/DMesh/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/MonkeyIsNull/DMesh)](https://github.com/MonkeyIsNull/DMesh/releases/latest)
![Go version](https://img.shields.io/github/go-mod/go-version/MonkeyIsNull/DMesh)
![platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)
![serverless](https://img.shields.io/badge/serverless-yes-brightgreen)
![status](https://img.shields.io/badge/status-pre--alpha-orange)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**A serverless mesh where your sessions don't die.**

DMesh is a resilient, serverless peer-to-peer overlay mesh written in Go. Nodes find each other and connect directly — no central server, nothing to host, nothing to knock out — and your sessions survive roaming, drops, and reconnects instead of starting over.

> Status: pre-alpha.

## Quick start

```sh
go install github.com/MonkeyIsNull/DMesh/cmd/dmesh@latest    # or: go build ./...

# create a network key once, then install the SAME key on every peer
dmesh network-key gen                  # prints a base64 key (store it safely)
dmesh network-key set <base64-key>     # run on each peer

# bring the node up: find peers, connect, and show a live status view
dmesh up --label laptop
```

A node is identified by its public key (an Ed25519 node ID). The network key is a shared secret that gates the mesh — without it, `dmesh up` won't start. Peers are found automatically over the LAN (mDNS) and learned from each other beyond it (gossip).

## Send a file (it resumes if the link drops)

```sh
dmesh recv --out ./downloads           # receiver
dmesh send <node-id> ./bigfile.iso     # sender
```

The transfer is anchored to the peer's identity, not its address — so if your network blips or you roam (wifi to cellular), it pauses and picks up byte-exact where it left off. Both ends print a SHA-256 on completion so you can confirm the bytes match.

## Why DMesh?

- **Sessions survive.** A blip or a roam pauses a transfer and resumes it, instead of restarting.
- **Serverless.** No control plane, lighthouse, or controller — nobody in the path deciding if you may connect, and nothing to take down.
- **Finds its own peers.** Zero-config mDNS on the LAN, gossip beyond it, or `--peer IP:PORT` to dial directly.
- **Works off-LAN.** Relay through any reachable member when a direct path isn't available (see below).
- **Permissioned.** A shared network key is required; an optional allow-list restricts the mesh to specific nodes.
- **Local-first.** Keeps working on a LAN with no internet and no coordinator.

## How it compares

| | control plane | sessions survive drops | serverless |
|---|:---:|:---:|:---:|
| Tailscale / Nebula / ZeroTier | yes (server / lighthouse) | no | no |
| Yggdrasil / libp2p | no | no | yes |
| Mosh | — (point-to-point) | yes (one shell) | — |
| **DMesh** | **none** | **yes (any session, whole mesh)** | **yes** |

## Commands

```sh
dmesh id [--label NAME]                 # print (and on first run, create) this node's identity
dmesh network-key gen|set|show|clear    # manage the shared network key
dmesh up [flags]                        # run the node + live roster view
dmesh members                           # print the gossiped roster once and exit
dmesh send <node-id> <file> [flags]     # open a durable session and stream a file
dmesh recv [--out DIR] [flags]          # accept one inbound session to a file
dmesh trust <node-id> [label] | list    # manage the allow-list
```

Common flags: `--label NAME`, `--port N`, `--no-mdns`, `--peer IP:PORT` (dial a peer directly; repeatable), `--trust-only` (admit only allow-listed peers), `--relay` (offer to relay for others), `--chaos` (on `send`, force a mid-stream pause/resume for testing). `DMESH_CONFIG_DIR` picks the config/identity directory; `DMESH_NETWORK_KEY` can supply the key via env.

## Off-LAN: relay

When two peers can't reach each other directly, run a reachable node as a relay (`dmesh up --relay`); credentialed members open a circuit through it and carry their end-to-end encrypted session over it. The relay is a dumb pipe — it forwards sealed frames it can't read, only between the two ends of a circuit, with bandwidth and circuit caps. A relayed session migrates to a direct path the moment one is available. Hole punching (direct off-LAN paths) is next.

## Try it on one machine

Two nodes on one laptop, no second machine and no mDNS — each with its own config dir and the same key:

```sh
DMESH_CONFIG_DIR=/tmp/a dmesh network-key gen            # copy the printed key
DMESH_CONFIG_DIR=/tmp/b dmesh network-key set <key>
DMESH_CONFIG_DIR=/tmp/a dmesh id                         # note A's node id

DMESH_CONFIG_DIR=/tmp/a dmesh recv --no-mdns --port 9001 --out ./dl
DMESH_CONFIG_DIR=/tmp/b dmesh send --no-mdns --peer 127.0.0.1:9001 --chaos <A-node-id> ./bigfile
```

`--chaos` forces a real pause/resume mid-transfer; the matching SHA-256 on both ends proves the bytes survived it.

## Build

```sh
go build ./...
go test ./...        # offline, deterministic
go test -race ./...
```

Requires Go 1.26+. On macOS, the first LAN run may prompt for *Local Network* access (mDNS); the test suite never touches multicast.

## Honest limitations (pre-alpha)

- **Permissioned ≠ per-node by default.** With no allow-list, anyone holding the network key is admitted (trust-on-first-use). Set an allow-list or `--trust-only` for per-node control. Signed invites / a small CA are planned.
- **Membership trust.** A credentialed member can currently forge membership facts about others; the fix (per-node signed membership updates) is planned. The allow-list bounds who can do this.
- **Relays see metadata.** A relay learns who talks to whom, how much, and when, and can drop traffic — but never reads your payload (it's end-to-end encrypted). Prefer-direct limits a relay's window.
- **Resume is bounded.** A paused session is held for a grace window, then torn down; off-LAN resume depends on a reachable path (direct or relay).

## Roadmap

Done: SWIM gossip membership (v0.2), durable/resumable sessions (v0.3), NAT traversal via reflexive discovery + relay (v0.4). Next: hole punching (direct off-LAN paths) → topology dashboard → virtual-interface (TUN) mode.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Adam Guyot.
