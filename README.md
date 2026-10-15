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

> ⚠️ **Status: pre-alpha.** v0.1 ships the **foundation only**: two credentialed nodes on a LAN discover each other over mDNS and exchange encrypted, mutually-authenticated messages with zero config, while an uncredentialed peer is rejected. The hero features — durable/resumable sessions, gossip membership, NAT traversal/relay, the topology dashboard — are later milestones.

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
fingerprint, then a table of known peers (ID, label, endpoint, link state, last-seen).

> **macOS note:** the first LAN run may raise a *Local Network* permission prompt for
> mDNS. CI and the offline test suite never touch multicast; the real-mDNS path is
> only exercised under `DMESH_MDNS_E2E=1`.

## Roadmap

Later milestones, in order: gossip membership (SWIM) → NAT traversal / relay → **durable/resumable sessions** (the hero feature) → topology dashboard → virtual-interface (TUN) mode.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Adam Guyot.
