# The Open System

The Open System (TOS) is a multichain blockchain system built around a tightly integrated node, operator, wallet, and API surface.

TOS is built around workchains, shardchains, message-driven execution, and high-throughput design, while organizing the product around clearer standards, stronger operator workflows, and a more coherent developer experience.

The project direction is simple:

- one canonical node runtime
- one canonical machine-facing API surface
- one canonical operator path
- one coherent wallet and contract flow

## What TOS Focuses On

TOS is designed for:

- validator and infrastructure operators who need reliable node workflows
- wallet and backend integrators who need stable read, estimate, send, and track semantics
- contract teams who need a predictable path from deployment to observation

The system is node-first, API-first, standards-first, and operator-first.

## Features

- ✅ Multichain architecture with masterchain, workchains, and shardchains
- ✅ Message-driven execution model inspired by the actor model
- ✅ High-throughput design aimed at large-scale user and application workloads
- ✅ Catchain-based consensus foundation with ongoing Simplex-oriented convergence work
- ✅ Embedded JSON-RPC service in `validator-engine`
- ✅ OpenAPI-based public API definition in [`doc/openapi.yaml`](doc/openapi.yaml)
- ✅ Canonical operator workflow through `tosctl`
- ✅ Health, readiness, metrics, and machine-facing node operations
- ✅ Wallet send, estimate, and track semantics documented as standards
- ✅ Standards map covering RPC, wallet, trust, indexing, operator, and application surfaces
- ✅ TOS Connect design for wallet-to-dApp flows
- ✅ TOS DNS
- ✅ TOS Sites and RLDP HTTP proxy support
- ✅ ADNL, DHT, RLDP, QUIC, and validator networking stack
- ✅ Trust-tier and verification model for different client types
- ✅ Transaction history and indexed-data contracts for explorers and backends
- ✅ Token and application standardization work (`TEP`-style surfaces)
- ✅ Privacy architecture work for actor-based private asset flows
- ✅ EVM workchain design path for Solidity and Ethereum-compatible contract deployment

## Architecture

TOS is organized around a few core principles:

- The node is the root of truth.
- Public APIs should come from the node, not from fragmented sidecar stacks.
- Operator workflows should be automatable and not depend on tribal knowledge.
- Standards matter as much as protocol mechanics.
- External users should see an integrated system, not a collection of loosely connected tools.

At the protocol level, TOS continues to build on a multichain model with heterogeneous execution domains. That includes the TVM-based base system and an explicit design path for an EVM workchain.

## Build

Build instructions are available in [`BUILD.md`](BUILD.md).

## LICENSE

This repository is licensed under the GNU General Public License v3.0. See [`LICENSE`](LICENSE).

TOS is built on top of foundational work originally developed by Telegram, EverX, Erigon, and RSquad Blockchain Lab. This repository continues that line of work as its own system while explicitly acknowledging those prior technical foundations.
