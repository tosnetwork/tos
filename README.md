# TOS Blockchain

TOS is an open-source Layer-1 blockchain implementation. This repository is
the base-layer codebase for the TOS network: consensus, sharded chain
validation, native TVM execution, smart-contract tooling, node software,
networking, cryptography, and operator interfaces.

It is intentionally focused on blockchain infrastructure. Application
products, marketplaces, model runtimes, and other higher-layer services are
outside this repository's scope.

## Core Components

- Masterchain and shardchain validation, Catchain, validator selection, and
  configuration management
- Native TVM execution, cells, blocks, messages, gas accounting, and smart
  contract primitives
- Full-node and validator-engine processes, JSON-RPC, Lite Client, and chain
  state tooling
- ADNL, DHT, RLDP, QUIC, overlays, DNS, and TOS Sites networking
- Wallet, key, cryptographic, database, indexing, and serialization libraries
- Fift, FunC, Tol, C++, and Rust tooling for contracts and operators

## Build

Use an out-of-source CMake build:

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target validator-engine create-state -j2
```

Rust operator tooling is in `tosctl/src`:

```bash
cd tosctl/src
cargo build
```

See [BUILD.md](BUILD.md) for prerequisites, compiler guidance, build targets,
and formatting rules.

## Repository Layout

- `crypto/` — TVM, cells, block logic, smart contracts, and genesis tooling
- `validator/` — consensus, validation, full-node, Catchain, and networking
- `validator-engine/` — validator node process and JSON-RPC server
- `lite-client/` — command-line chain client
- `tosctl/` — Rust operator and node-control tooling
- [`tosnetwork/doc`](https://github.com/tosnetwork/doc/tree/main/tos-blockchain) — protocol, configuration, operator, and development documentation
- `third-party/` — vendored dependencies

## Documentation

Blockchain documentation is maintained in the
[`tosnetwork/doc`](https://github.com/tosnetwork/doc/tree/main/tos-blockchain)
repository.

- [Documentation index](https://github.com/tosnetwork/doc/blob/main/tos-blockchain/README.md)
- [Build guide](BUILD.md)
- [Validator guide](https://github.com/tosnetwork/doc/blob/main/tos-blockchain/Validator.md)
- [Full-node guide](https://github.com/tosnetwork/doc/blob/main/tos-blockchain/FullNode.md)
- [Lite Client guide](https://github.com/tosnetwork/doc/blob/main/tos-blockchain/LiteClient.md)
- [Configuration parameters](https://github.com/tosnetwork/doc/blob/main/tos-blockchain/ConfigParam.md)

## License

TOS is licensed under the [GNU General Public License v3.0](LICENSE).
