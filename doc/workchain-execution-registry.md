# Workchain Execution Registry

The workchain execution registry is the host-chain mechanism that maps a workchain descriptor from `ConfigParam 12` to a local execution engine.

## Current Scope

This repository currently ships the native TVM execution path for actor-based applications.

The default registry registers the TVM descriptor engine only:

| Engine | Descriptor key | Status |
|---|---|---|
| TVM | `wfmt_basic`, `vm_version = -1` | active |

No additional engine keys are registered or advertised by the node.

## Behavior

When a non-masterchain workchain appears in `ConfigParam 12`, the validator resolves its descriptor through the registry. If the local binary has no matching engine, validation fails rather than falling back to TVM.

This keeps unknown execution domains fail-closed.

## Future Engine Policy

Any future engine outside the native TVM surface must define:

- descriptor key and versioning rules
- account execution policy
- config validation
- compute semantics
- migration rules for active networks
- tests for collator and validator paths

Until such an engine exists and is registered, this binary remains focused on native TVM execution.
