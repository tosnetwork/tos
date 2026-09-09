# Initial instance identity implementation status

D52 revision at memo `58c24c91` permits the one-time predicate: the authenticated
predecessor ledger lacks this workchain and the proposed configuration contains
its descriptor. The source checkpoint is `ce1db0695`. This is an intermediate
implementation, not a completed D40/D52 or milestone acceptance claim.

## Implemented in this checkpoint

- New mandatory `McStateExtra` auxiliary reference, independently keyed ledger,
  explicit empty zerostate initialization and authenticated read access.
- Identity-bearing engine shell with mandatory genesis/instance fields, retaining
  the historical K acceptance interval. No old-constructor fallback.
- Native cell representation identity hashing of versioned domain, authenticated
  genesis, workchain, historical ConfigParam 12 descriptor hash and issued seq.
- First-installation configuration reconstruction, seq exactly 1. Existing keys
  are never overwritten. There is no successor increment path in this phase;
  future successor issuance requires a checked increment and authenticated handover.
- Existing-instance configuration checks use the historical ledger descriptor,
  not the updated descriptor. Changing the instance ID rejects as unsupported
  successor issuance; repeated ordinary configuration observation preserves state.
- `check_mc_state_extra` reconstructs wc=2's permitted root from the predecessor
  and proposed configuration, then compares the entire candidate root. Other keys
  are retained. The producer integration is not present yet.

The complete-root comparison includes blind writes and deletions of unrelated
keys, regardless of whether their previous values were read. Reconstruction uses
persistent cell sharing; it does not copy the full ledger. ConfigParam 84 decoding
currently reuses the existing table decoder; no new D31 resource certification is
claimed. An unavailable authenticated predecessor path is local failure; invalid
candidate data rejects. Runtime calibration of those actor-level classifications
remains outstanding.

## Measured private functions

`test-workchain-instance-identity` is opt-in through
`TOS_WORKCHAIN_INSTANCE_TESTS`, registered in `crypto/CMakeLists.txt`. It calls the
production reconstruction and ledger routines, not a test-created checker. Its
minimal configuration fixtures are not complete consensus-valid block fixtures.

The positive configuration reconstruction checks a successful installation,
seq=1, exact creation-descriptor commitment and the resulting expected root.
An updated descriptor with the same installed identity preserves that root.
A separate explicit attempt to issue the same workchain again rejects. These
are different operations: re-observing installed configuration is not reissuing.

Six isolated, compiled source mutations have byte restoration and reapplication
hash audits in `doc/measurements/uno-d40-controls-ce1db0695/report.json`:

| Mutation | Failure identities | Meaning |
| --- | --- | --- |
| Remove full-root comparison | 804 / 805 / 848 | Changed ledger / unrelated deletion / deletion before re-trigger |
| Treat missing ledger as empty | 803 | Missing state is not initialization |
| Overwrite issued entry | 846 | Second explicit first issuance must reject |
| Use current descriptor | 814 | Ordinary descriptor update must retain identity |
| Leak failed staging into predecessor | 808 | Failed issuance cannot change predecessor root |
| Reject every first installation | 840 | Legal first installation must succeed |

804/805/848 are three inputs exercising ONE guard, not three independent guards.
All restore builds explicitly name `tos_block`, `tos_validator` and
`test-workchain-instance-identity`; the only executable run by this driver is
the latter. Compiler, build and runtime subprocess layers are recorded. Raw
stdout/stderr are preserved, including empty streams. Initial compilation errors
are retained as development failures, not behavior evidence.

## Still required before delivery

1. Collator producer call, after configuration validation and before installation.
   `collator.cpp` remains reserved to A at this checkpoint.
2. Migration of all existing shell construction sites and frozen state fixtures;
   the mandatory constructor signature intentionally has no compatibility default.
   Standard WorkchainBlock regression has not been rebuilt/run for this checkpoint.
   Earlier green binaries are not evidence for this wire revision.
3. Actual validator typed-result/call-site controls. In particular, removing the
   call in `check_mc_state_extra` has NOT been shown to fail these private tests.
   Compiling the full `tos_validator` target is not that behavioral evidence.
4. Complete regression after those integrations, explicit rebuild of executable
   leaves of affected drivers, and source-bound fixture/generator provenance.

No deployment configuration, activation capability or final commit gate has been
opened. Successor issuance is unsupported and explicitly rejected. First issuance
exists in the reconstruction function, but has not yet been observed committing
through the collator/masterchain pipeline.
