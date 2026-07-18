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
