# Block preflight: contract and incremental implementation

## Implementation checkpoint: structural accumulator only (2026-09-06)

`crypto/block/workchain-input-preflight.h` now implements a bounded accumulator
for the union of multiple input roots. It is **not yet called by production
admission, dispatch or replay**. B3-1/M-2 therefore remain open; this checkpoint
does not protect the earlier commitment/inbox paths or bound proof execution.

The API takes explicit Cells, payload bits and root-call limits; it defines no
production defaults and does not reuse engine `wire_bytes`. Repeated root calls
consume the root budget even when their Cells were already visited. All roots
and reachable ordinary Cells count, with hash deduplication across calls.
Failures are sticky, including unavailable data. No partial traversal becomes
an accepted cache. This utility admits only complete non-virtualized ordinary
input Cells; adopting that contract at a consensus entry point requires the
resolved versioned policy, not an incidental parser behavior change.

The iterative DFS admits at most the configured number of distinct Cells,
checks that limit before loading the next one, and checks payload bits before
visiting children. It uses an ordered hash set (not a hash-table collision-cost
assumption); memory is bounded by admitted Cells and pending edges, with at
most four new edges per admitted Cell. It does not serialize a BoC, decode an
inbox, traverse previous-state/configuration roots, or allocate C++ recursion
frames. This is an operation-count argument, not a measured cold-load/RSS bound.
Local allocation failures are not converted into invalid-transaction results.

Four tests cover hand-counted two-root sharing and exact/one-over bounds,
observed loading of the first over-limit child, a depth-1024 four-way-shared
graph, and unavailable/special/missing input. Each new test was demonstrated
red with a targeted mutation:

| Mutation | Observed failure |
|---|---|
| Remove Cell limit | Child load count becomes 1 instead of 0 |
| Remove bit limit | One-bit-over second root is accepted |
| Remove deduplication | Legal deep shared graph exceeds the Cell limit |
| Admit special Cells | Merkle-proof input is accepted |

All mutations were restored; all 46 WorkchainBlock tests pass. Logs are in
`build/preflight-{cell,bits,sharing,special}-mutation.log` and
`build/preflight-workchain-regression.log`. No physical-transaction constraint,
partition schema, config encoding or shared Native account limit changed.

Next integration must establish the resolved policy and bound collator import
collection and validator InMsgDescr traversal *before* full inbox construction;
replay's claimed-witness extraction must be bounded before its existing state
decode. A dispatch-only gate is explicitly insufficient. Commitment building
and full inbox validation must then obey the frozen order, with instrumented
zero-invocation tests at those boundaries. Semantic/action/proof-cost preflight,
cold resource measurements and collator/validator path tests remain required.

## Design baseline

This addresses audit M-2. It defines an implementation direction, not a frozen
configuration, implemented protection, or accepted resource gate. H-2 and the
single-account state-capacity decision remain separate open items.

## Current evidence

`execute_resolved_workchain_block` in
`crypto/block/workchain-execution-dispatch.cpp` encodes the committed input,
extracts the previous executor state, executes the engine, and only then checks
the returned `WorkchainBlockResourceUsage` against the resolved policy.

The Counter engine reports eight `wire_bytes` for its numeric payload. Its
candidate can also reference a message dictionary. A serialized container size
is therefore not a substitute for this existing engine-defined field. Reducing
the existing wire limit to seven rejects the result after execution; it does
not bound execution cost.

`encode_workchain_block_input` decodes the inbound envelope dictionary before
execution. A preflight immediately before `execute_block` would be too late to
bound that earlier decode. Earlier receiver/collator parsing and transport must
also retain their own bounds; a dispatch check cannot retroactively protect them.

## Proposed two-layer contract

1. Host structural admission: explicit limits on distinct reachable Cells and
   their payload bits, separately named from engine `wire_bytes`. Count the union
   reachable from the candidate and optional inbound dictionary, including the
   roots. Count shared Cells once by authenticated hash, including sharing
   between those two roots. All references reachable from these untrusted roots
   count, even if they point into data also used by previous state.
2. Engine semantic preflight: bounded canonical parsing of the admitted payload,
   action/proof-length checks and cheap declared-cost checks before proof
   verification or state application. Repeated logical actions count repeatedly
   even when their Cell representation is shared. Structural deduplication is
   not a discount on proof verification or state updates.

Neither metric measures the complete block's transport bytes or RSS. Do not
traverse the committed input wrapper as the structural root: it also references
the entire previous shard state, configuration and finality context. Those have
separate authentication/acquisition/resource requirements; including them would
turn this admission check into a growing-state scan on each block.

Run host structural admission before `encode_workchain_block_input`, state
extraction and engine execution in the resolved dispatch path. Inspect earlier
callers separately for expensive parsing before that boundary. Keep result
validation and all existing post-execution usage checks: preflight cannot prove
actual written-state cost or replace replay.

## Boundedness and API reuse

The walker must stop on the first over-limit Cell/bit count, bound its visited
set and traversal stack, and propagate incomplete or invalid Cell errors. It
must not serialize the entire BoC merely to learn its size. Freeze special-Cell
and depth semantics as part of this contract, not as incidental parser behavior.

`vm::CellStorageStat` already has `limit_cells`, `limit_bits`, hash deduplication
and early rejection. It is a reuse candidate, not yet selected: its recursive
traversal needs a depth/stack audit. All `compute_used_storage` overloads call
`clear()`, which calls `clear_limit()` and resets both limits to their maximum.
Setting limits before calling that method silently disables them. A reuse path
would need a fresh accumulator with explicit limits and `add_used_storage`
across both roots, without clearing deduplication between roots. This does not
by itself prove bounded cold Cell loads, hashing or memory usage.

The limits must come from authenticated, versioned engine policy and have
explicit nonzero bounds. A local operator setting must not determine consensus
acceptance. Numerical production limits, policy encoding, activation boundary
and any required engine-version change remain to be frozen; do not derive them
from the Counter's eight-byte fixture or silently reinterpret existing fields.

## Required acceptance evidence

- Count roots, shared children, two-root sharing and repeated logical actions
  with independently calculated small fixtures.
- At-limit candidates execute; one-Cell/one-bit-over candidates invoke the
  engine zero times. Mutating away preflight must make the invocation assertion
  fail, independently of rejection wording or a later result-limit failure.
- Exercise empty and maximal legal inboxes and failures before inbox decoding;
  show no state application or proof verification on failed semantic preflight.
- Exercise deep, highly shared and incomplete/special graphs under the frozen
  semantics, and measure visitation/load/allocation bounds on cold inputs.
- Retain Counter payload accounting and full-wrapper replay vectors unchanged
  unless an explicitly approved version transition requires otherwise.
- Drive both collator preparation and validator reconstruction through the
  same resolved policy and admission checks. An engine unit test alone is not
  evidence that both callers enforce them.

M-2 stays open until these checks are implemented and exercised. This note
does not establish a slot duration, production memory bound, or scalable state
synchronization.
