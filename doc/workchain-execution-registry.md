# Workchain Execution Registry

The workchain execution registry is the host-chain mechanism that maps a workchain descriptor from `ConfigParam 12` to a local execution engine.

## Current Scope

This repository currently ships the native TVM execution path for actor-based applications.
AI actor features are expected to compose through native contracts and asynchronous messages, not through additional execution engines.

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

AI actor roadmap work must not add an execution engine as a shortcut for model, service, or agent integration. Those integrations should be represented as native service actors, off-chain workers with on-chain authorization, or proof adapters.

## Cross-Chain Bridge Contracts

The `crosschain/` directory vendors bridge smart contracts whose Solidity half is deployed on external counterparty chains (Ethereum, BNB Smart Chain, ...), never inside the TOS node. The TOS-side half of each bridge is ordinary native TVM code selected through masterchain ConfigParams. Vendoring these sources does not register an execution engine, add a workchain descriptor, or weaken the native-TVM-only policy above, and the CI scan excludes `crosschain/` for that reason.
