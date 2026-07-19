# Native Security Audit Notes

This note covers the native TOS build and its focused TVM execution surface.

## Scope

In scope:

- masterchain and basechain validation
- TVM transaction execution
- native zero-state generation
- validator and collator paths
- lite-server and JSON-RPC surfaces used by native tooling
- wallet and token indexing for wc=0

Out of scope:

- execution domains outside the native TVM surface
- RPC namespaces for unsupported execution domains
- genesis templates for unsupported execution domains

## Current Release Gate

The canonical zero-state template registers only wc=0. Any future execution domain outside the native TVM surface must be introduced as a separate feature with its own implementation, tests, threat model, and audit.

AI actor primitives such as agent accounts, task escrow contracts, service actors, and verifier actors require dedicated review before production use.
