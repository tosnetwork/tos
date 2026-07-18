# Security Policy

This repository currently ships the native TVM execution path only.

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

## Reporting

Report suspected vulnerabilities privately to the project maintainers. Include:

- affected commit or release
- affected component
- reproduction steps
- expected and observed behavior
- exploitability and impact assessment if known

Avoid publishing exploit details before maintainers have had time to triage and patch.

## Custom Workchains

Custom execution domains are outside the current security scope. If any are introduced in the future, they require fresh threat models, dedicated audits, and release gates before production use.
