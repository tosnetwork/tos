# The Fast Blockchain for AI Agents

**The Open System (TOS)** is the fast actor-model blockchain for AI agents: autonomous wallets, asynchronous coordination, verifiable workflows and native on-chain payments built for the emerging agent economy.

TOS treats accounts, smart contracts, AI agents, tools, services and tasks as independent actors. They communicate through asynchronous messages, maintain private state, and compose into scalable workflows across the native TVM execution layer.

This repository builds and ships the native TOS protocol stack. The node registers the native TVM engine and keeps a focused execution surface for actor-based applications.

## Direction

TOS is being developed as a practical coordination and settlement layer for AI-native applications:

- agent wallets with persistent identity, policy, balances and task history
- independent AI agents with persistent on-chain identity, state and balances
- agent-to-agent and agent-to-service messaging through native asynchronous execution
- task contracts for escrow, result submission, acceptance, disputes and payout
- capability registries for model providers, data providers, tools and compute services
- verifiable workflows with signed results, attestations and external evidence
- native payments for model calls, data access, tools, compute and task completion

TOS is not primarily targeting consumer Android or iOS wallet applications. The wallet direction is agent-first: accounts and wallets are built for autonomous agents, automation systems and service actors that need programmable authority and auditable settlement.

See [ROADMAP.md](ROADMAP.md) for the technical roadmap.

## What Is Included

The repository includes:

- TVM execution, cell serialization, Fift and FunC tooling
- masterchain and shardchain validation logic
- validator engine, full-node networking, ADNL, DHT, RLDP and QUIC support
- JSON-RPC surfaces for native node, account, block, transaction and token operations
- `tosctl` node-control, configuration and operator tooling
- genesis and smart-contract build scripts for the native chain

## Execution Model

Native execution provides the foundation for AI actor workflows:

- deterministic cell-native account state
- asynchronous message delivery and bounce semantics
- gas accounting in nano-TOS
- dynamic shard split and merge behavior
- masterchain-rooted consensus, validator sets and configuration updates

Each account behaves as an independent actor. Contract calls are messages delivered to an account inbox; execution mutates only that account and may emit outbound messages. This model maps naturally to AI agents, task queues, service actors and multi-step workflows.

## Build

Build instructions are in [BUILD.md](BUILD.md). The primary C++ targets are:

- `validator-engine`
- `create-state`
- native networking and protocol libraries
- TVM, Fift and FunC tooling

Rust operator tooling is under `tosctl/src`.

Common verification commands:

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target create-state validator-engine -j2
cd tosctl/src && cargo check -p contracts -p chain-rpc-client -p common -p commands -p service
```

## Repository Layout

- `crypto/` - TVM, cells, block logic, smart contracts and genesis tooling
- `validator/` - validation, full-node, catchain and consensus components
- `validator-engine/` - node process and JSON-RPC server
- `tosctl/` - Rust node-control and operator tooling
- `doc/` - protocol, configuration and operator documentation
- `third-party/` - vendored dependencies

## Useful Targets

- `validator-engine`
- `create-state`
- `func`
- `fift`
- `toslib`

## License

This repository is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE).
