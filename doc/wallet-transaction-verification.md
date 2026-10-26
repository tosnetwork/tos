# Bounded wallet transaction verification

`tos_proof_verify_wallet_transaction` is a synchronous, read-only C ABI for
mobile history and receipt verification. It decodes a raw transaction using the
node's cell/TLB implementation, including valid opaque library-reference bodies.
It never executes a body or resolves a library.

The caller supplies basechain account bytes, an unsigned 64-bit logical time,
and a transaction hash obtained from an independently authenticated account
head. Subsequent history reads bind to the previous hash/time returned by the
last verified transaction. RPC summaries, block identifiers and phase flags are
not authentication inputs. This API does not establish a trusted chain anchor,
prove recipient credit, estimate fees, sign, broadcast or persist anything.

A successful call means the complete BOC, root hash, account, logical time and
transaction layout match. It does **not** mean a payment happened. A caller
tracking a payment must additionally match the signed external message hash and
an actual committed outgoing internal message's source, destination, amount,
body hash and non-bounced status, together with its required execution policy.
Compute/action success alone is insufficient: a send can be skipped while both
phases succeed and the wallet nonce advances.

## Interface and failure behavior

See `lite-client/proof-verify/embedded.h` for borrowed pointer lifetimes and
return codes. Output is a length-delimited JSON object tagged
`tos-wallet-transaction/1`. Hashes use lowercase hex; standard addresses use raw
`workchain:hash`. Unsupported nonstandard addresses are represented as null.
Logical times, fees and message values are decimal strings; timestamps, exit
codes and bounded counters are JSON integers. Message bodies are represented
only by their hashes. No arbitrary body bytes are copied into JSON.

The result includes the predecessor, fees, incoming/outgoing messages and
ordinary transaction compute/action phases. Other transaction types are tagged
`other`; they cannot acquire an inferred payment-success flag. The API adds no
`paid` or top-level execution-success field.

Invalid interface inputs return -1, verification refusals -2, insufficient
result capacity -3 and caught internal exceptions -4. After validating the
output pointer/capacity, failures leave its entire capacity zeroed and length
zero. An invalid output pointer/capacity is refused without clearing its range.
Callers must provide valid, mutually disjoint pointer ranges and serialize their
own account observations/checkpoints. The function has no asynchronous handle.

## Resource inventory

All allocations are local to one call and are released on success, refusal,
capacity failure or caught exception. There are no caches, actors, queues,
timers, descriptors, threads, files or retained input/output buffers.

| State | Local limit and full behavior |
| --- | --- |
| Borrowed BOC | 1 MiB, checked before native allocation; empty/oversized inputs refused |
| Preflight links | 16,384 entries, each four reference indices and one count; header checked before allocation |
| Preflight depths | 16,384 integers; acyclic forward references and depth <= 1,023 checked before deserialization |
| Native cells/index | At most 16,384 cells from at most 1 MiB of serialized bytes; each DataCell storage <= sizeof(DataCell) + 4*sizeof(LevelInfo) + 128 bytes; native BOC index arrays are proportional to the same bounded cell count |
| Typed layout traversal | At most 65,536 referenced-schema visits, including shared subgraphs; exhausted budget refuses the layout |
| Output dictionary traversal | At most 256 messages; count checked before traversal, traversal stops if actual count exceeds the declaration; every consecutive index must exist |
| Rendered JSON | Fixed fields, at most 256 fixed-shape message summaries; addresses <= 76 characters, hashes 64, currency strings <= 37, logical times <= 20; bodies never rendered. Result additionally capped at 1 MiB |
| Borrowed output clearing | At most 1 MiB, checked before clearing |

The API does not control how many threads a caller creates. Mobile integrations
must retain their bounded proof/history admission permits. The bounds above
apply independently to each admitted synchronous call, without global storage.
Object/allocator overhead is additional; these allocation bounds are not an
exact process RSS claim.
This change makes no performance claim for validator production hardware.

## Reproduction and scope

Build `tos-proof-embedded` and `test-proof-verify-embedded`, then run:

```
ctest --test-dir build --output-on-failure --no-tests=error \
  -R '^(wallet-transaction|proof-verify-embedded)$'
python3 scripts/test-wallet-transaction-controls.py --build-dir build
```

The control runner checks the invoked Git checkout and byte-matches its codec,
ABI, tests and fixtures against the configured CMake source before any write.
The configured compile source may be a matching copy without Git metadata.
It verifies the baseline,
removes one guard at a time, requires a failure at its named runtime assertion,
and restores/rebuilds the original bytes in `finally`, checking exact restoration. Run it in an isolated
checkout without concurrent builds or processes using its shared library.
It covers hash/account/time binding and the byte/cell/depth/message ceilings, plus full typed-layout validation.
The handwritten transaction schema validates typed StateInit, state updates,
descriptions and dictionary leaves while keeping code/data/Any bodies opaque.
The chain workflow builds this ABI and runs both the regression and controls.

The three small frozen transactions in `test/pq-native/data/wallet-transactions`
come from a temporary three-validator public-genesis network running source
`295d5029b2a465e9e17a332c34acb1eac475cca3`. Their manifest includes byte hashes,
transaction hashes and the independently authenticated source head. The newest
contains an opaque library cell, skipped action and no outgoing message; the two
predecessors each contain a 10 TOS outgoing message. No key or runtime database
is included. These are native public-test-signer fixtures, not proof of mobile
protected-custody signing or end-to-end mobile payment acceptance.

Synthetic cases cover exact 1 MiB bytes, 16,384 cells, 1,023 depth, 256 messages
and one beyond each, unsigned-64 logical time, full 120-bit fees/message values,
matching-hash malformed layouts, dictionary holes/count mismatch, failure
clearing, direct opaque body references, malformed referenced typed fields,
and concurrent independent calls.
