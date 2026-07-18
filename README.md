# The Open System

**The Open System (TOS)** is a TON-derived blockchain node focused on the native TVM execution layer.

This repository currently builds and ships the native TON-compatible protocol stack only. Custom execution domains have been removed from this tree; the node registers the native TVM engine and keeps the standard workchain configuration model for protocol compatibility.

## What Is Included

TOS keeps the actor-style, message-driven execution model inherited from TON. Accounts are independent actors with private state. Contract calls are asynchronous messages delivered to an account inbox; execution mutates only that account and may emit outbound messages.

The repository includes:

- TVM execution, cell serialization, Fift and FunC tooling
- masterchain and shardchain validation logic
- validator engine, full-node networking, ADNL, DHT, RLDP and QUIC support
- JSON-RPC surfaces for native node, account, block, transaction and token operations
- `tosctl` node-control, configuration and operator tooling
- genesis and smart-contract build scripts for the native chain

## Execution Model

Native execution provides:

- deterministic cell-native account state
- asynchronous message delivery and bounce semantics
- gas accounting in nano-TOS
- dynamic shard split and merge behavior
- masterchain-rooted consensus, validator sets and configuration updates

`ConfigParam 12` remains part of the protocol model, but this binary registers only the native TVM execution engine.

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
