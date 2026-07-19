# Configuration Parameters

This document tracks the configuration parameters used by the current native TOS build for actor-based applications.
AI actor features that need consensus-level activation, such as task deadline semantics, delivery failure records, or future service-actor pricing rules, should be introduced through explicit configuration and versioning rather than hidden local defaults.

The canonical TL-B schema is in [block.tlb](../crypto/block/block.tlb). Initial values are set during [zero state generation](Zerostate.md).

## Native TVM Scope

Additional execution-domain activation, gas, RPC, and chain-specific ConfigParam descriptions are intentionally absent from this native TVM tree.

The current node registers:

| Workchain | Execution | Descriptor |
|---|---|---|
| masterchain (`-1`) | consensus/config | reserved |
| basechain (`0`) | TVM | `vm_version = -1` |

## ConfigParam 12

`ConfigParam 12` stores the workchain descriptor dictionary. In the current build it should contain only the native basechain descriptor for wc=0.

Validators register the native TVM execution engine. A descriptor for an unsupported workchain would not be executable by this binary.

AI actor applications should be deployed as native TVM contracts on wc=0 unless a future approved protocol change defines otherwise.

## ConfigParams 6 and 7

ConfigParams 6 and 7 govern extra currencies. They do not define the native TOS supply.

The native TOS supply is set at zero-state construction time in the genesis template; see [Zerostate.md](Zerostate.md).

## Validator and Network Parameters

The remaining masterchain parameters follow the native TOS schema in [block.tlb](../crypto/block/block.tlb) and are consumed by the validator, collator, election, gas, storage, and networking code paths.

When adding or changing a parameter:

- update the TL-B schema if the cell shape changes
- update zero-state generation if the initial value changes
- add migration rules for active networks
- keep validator and collator validation paths consistent

## References

- [Zerostate.md](Zerostate.md)
- [block.tlb](../crypto/block/block.tlb)
