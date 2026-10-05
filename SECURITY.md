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

- The TOS Service Protocol stablecoin escrow v1 has been removed from the repository: no source, artifact or tooling for it remains, and a guard fails if any of it returns. Escrow v2 is supported only for non-production deployments because a payout refused by the recipient's jetton wallet can leave funds stranded; this is an accepted risk for the current version. See [crypto/smartcont/STABLECOIN-ESCROW.md](crypto/smartcont/STABLECOIN-ESCROW.md).
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
