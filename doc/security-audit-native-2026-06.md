# Native Security Audit Notes

This note covers the native-only TOS build.

## Scope

In scope:

- masterchain and basechain validation
- TVM transaction execution
- native zero-state generation
- validator and collator paths
- lite-server and JSON-RPC surfaces used by native tooling
- wallet and token indexing for wc=0

Out of scope:

- removed custom workchains
- deleted workchain-specific RPC namespaces
- deleted workchain-specific genesis templates

## Current Release Gate

The canonical zero-state template registers only wc=0. Any future custom execution domain must be introduced as a separate feature with its own implementation, tests, threat model, and audit.
