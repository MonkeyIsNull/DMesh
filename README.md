# DMesh

**A serverless mesh where your sessions don't die.**

DMesh (*"dou mesh"* — the French pronunciation of *D*) is a resilient, serverless peer-to-peer overlay mesh written in Go. Nodes find each other and connect directly — with **no central coordination server, nothing to host, and nothing to knock out** — and, unlike other meshes, the **sessions themselves survive** roaming, drops, and reconnects (Mosh's resilience, generalized to a whole mesh).

> ⚠️ **Status: brainstorming / pre-alpha.** No code yet — the design is taking shape in [BRAINSTORM.md](BRAINSTORM.md).

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

## Design

See [BRAINSTORM.md](BRAINSTORM.md) for the evolving architecture — identity-not-address, gossip membership, Noise-encrypted transport, permissioned membership, resumable sessions, and DoS resistance.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Adam Guyot.
