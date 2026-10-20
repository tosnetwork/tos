# Security Policy

This repository currently ships the native TVM execution path for actor-based applications.

## Supported Surface

Security review should focus on:

- validator and collator consensus paths
- masterchain and basechain validation
- TVM transaction execution
- zero-state generation
- JSON-RPC methods served by `validator-engine`
- lite-server, ADNL, DHT, RLDP, and QUIC networking
- wallet and token indexing for wc=0
- build, release, and deployment scripts

## AI Actor Security Scope

As TOS evolves toward AI-native actor workflows, security review should also cover:

- agent account ownership, delegation, recovery, and spending policies
- task contracts that hold escrow, enforce deadlines, and settle payouts
- service actors for model, data, tool, and compute access
- capability registries, metadata updates, staking, and reputation references
- asynchronous workflow messages, callbacks, retries, timeouts, and cancellation paths
- result verification metadata, signed responses, attestations, and external evidence references

Agent workflows should be designed so that balances, task state, permissions, and settlement rules remain auditable from chain state.

## Accepted Risks and Removed Contracts

- The TOS Service Protocol stablecoin escrow (v1 and v2), the third-party stablecoin reference contracts and the liquid-staking suite have been removed from the repository and are outside the supported scope: no source, artifact or tooling for them remains, and a guard fails if any of the escrow returns. Removal is a scope decision, not a fix of those contracts' protocols; it migrates no existing deployment and recovers no funds held by one.
- The token bridge must not be activated in production while its pre-mainnet checklist is incomplete, and an operation left in flight follows the incident procedure in [crosschain/token-bridge/SECURITY.md](crosschain/token-bridge/SECURITY.md).

## Reporting

Report suspected vulnerabilities privately to the project maintainers. Include:

- affected commit or release
- affected component
- reproduction steps
- expected and observed behavior
- exploitability and impact assessment if known

Avoid publishing exploit details before maintainers have had time to triage and patch.

## Execution Scope

Execution domains outside the native TVM surface are outside the current security scope. If any are introduced in the future, they require fresh threat models, dedicated audits, and release gates before production use.
