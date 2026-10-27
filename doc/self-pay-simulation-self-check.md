# Self-pay simulation prototype author self-check

Implementation: `a6c82a96a`, preceded by the isolated bounded-preflight refactor
`27de5e12e`, on `feat/self-pay-simulation`. This is an internal WIP, not a
merge-ready fee API. No mobile call site or broadcast path is enabled.

## Changed boundaries and checklist areas

Applicable areas: upstream comparison; determinism; input/resource bounds;
cryptographic authorization; native codecs/proof authentication; build and
artifact provenance; tests/evidence; documentation drift. Consensus selection,
network transport, persistence and secret-key custody are not changed.

`simulate_self_pay` authenticates a live read before preparing the same-target
configuration and account and executing the exact external-message bytes.
`execute_prepared_self_pay` is the internal prepared-input boundary. A search of
`lite-client` and `test/pq-native` found only the adapter and the native test as
callers; the C ABI, CLI, Swift and JNI have no simulation entry point yet.
`preflight_wallet_boc` reuses the existing byte/cell/depth check; account preflight
was factored separately so it can run before the existing read verifier decodes
account cells. Existing transaction verification behavior is retained.

No proof input is interpreted as a signing grant. The returned live next-state
must be persisted before using its estimate; broadcasting additionally requires
an independently persisted outbox containing the exact signed BOC. This function
neither persists nor broadcasts, so it cannot release a pending authorization.

Only the fixed source-bound self-pay code profile, basechain and supported VM16
are modeled. A supplied frozen StateInit must match the authenticated current
frozen state hash; it need not match the birth address after data changes.
Active code must match the profile, and account-local or endpoint-supplied
libraries are refused. All signatures use the real native verifier. Explicit
clock/LT/previous-block data and a nonzero domain-separated seed avoid ambient
execution defaults. Seed binding includes target root/file, address and the
SHA-256 of exact wire bytes, separately from the message-root hash.

Import rejection and VM non-acceptance produce no transaction or fabricated fee
fields; -701 is not labeled universally as insufficient funds. Executed means a
local simulated transaction exists, not that payment succeeded or was confirmed.
The bounded transaction codec, expected balance and state hash are returned;
raw signed/transaction BOCs and the VM log tail are not returned.

The shared code hash is also checked by the existing source-generated Explorer
registry test. The mobile engine does not link the server registry. Frozen
fixture generation recompiles the contract and checks public diagnostic inputs
against the signature-verifying reference emulator. The checker requires all
22 generating sources, both input files, 13 named rows and the shared profile.

Upstream comparison: local `ton-c` at
`857b8a57a178e6ae0fe7fa86e7d81c5233de8560` has the ordinary transaction emulator
(`emulator/transaction-emulator.h`), reused here without modifying its execution
rules. Searching its lite-client and emulator found no `simulate_self_pay` or
`execute_prepared_self_pay`; the proof-bound fixed PQ profile is a local extension.

## Resources and lifetime

There is no new cache, queue, actor, socket, timer or production disk file. State
is local to one synchronous call and released on return, including refusals.
The borrowed material aggregate is checked against 64 MiB before read-material
copies, with at most 1024 chain responses and 16 descent links. Account TL is
preflighted before the read verifier's cell allocation: 16 MiB reply, 1 MiB
account state, 16384 account cells, 131072 combined proof cells. Complete config
preparation retains its 65536 loaded-representation and depth1023 bounds. Message
input uses the existing bounded wallet BOC preflight. Full inputs refuse instead
of accumulating requests. The consumer must serialize work and establish mobile
aggregate/concurrency limits before exposing this operation.

These are internal candidate limits, not proven phone budgets. The native VM's
execution and result allocations still require full platform/resource acceptance.
No production-hardware or worst-legitimate-input performance claim is made.

## Validation and remaining gates

See the companion memo evidence index for exact commands, exit statuses, source
and binary hashes, original failures and raw retained artifacts. Required checks:

- Native prepared-input and proof-composition suite: 29 named checks.
- Account-preflight refactor: 31 checks, 16 targeted source variants and restoration.
- Native execution controls: seed root/file/wire binding, code profile, frozen
  current state, import classification/no fabricated transaction, post-balance,
  historical refusal, actual ML-DSA/SLH verifier removal, forced-zero seed refusal
  and guard removal. The test source is never modified to make a product fault pass.
- Fixture gate: six tests, with source-closure removal causing the designated
  missing-source test to fail and restoration passing all six.
- Python lint/format, C++ formatting, YAML parse and CTest/build-call mapping.

The first PQ control linked the old shared proof library, whose VM symbols
interposed the variant. That all-green run is invalid sensitivity evidence.
The corrected runner uses the retained static engine; the resulting executable's
`otool -L` lists no proof dylib. Earlier receipts remain retained.

The branch has NOT yet incorporated refreshed main
`c1cb3b8d699daf037106fd5f000c53d79c40f295`; fixture provenance intentionally names
the sources it actually used. Integrate main and regenerate affected fixtures
before final acceptance. No full fresh CMake/native build, ASAN/UBSAN run, fresh
supported basechain proof-to-execution positive case, C ABI/schema, Apple/Android
build, device memory acceptance, final gas-margin/fee policy, or full mobile flow
has passed for this prototype. The recorded VM18 Elector composition only proves
authentication followed by an explicit unsupported-profile result. Independent
code review is still required; design review does not substitute for it.

This self-check records limitations instead of granting readiness. Do not merge
unused helpers or advertise estimates until the entire execution, public API,
platform, resource and fee-policy gates are met.

## Independent review correction

Review of `256bc1ad0` found that the fixture manifest omitted the interpreted
`crypto/fift/lib/Asm.fif` and default-preloaded `crypto/fift/lib/Fift.fif`.
The compiler executable hash does not cover those source files. A temporary
source-root counterexample accepted all twenty listed sources without either
Fift input. Checklist TE/provenance: the completeness assertion was too weak.
Both inputs are now required by generator and checker; no recursive include was
found in either current file. Inputs were actually regenerated, not relabeled.
The six fixture tests and native 29-check suite pass on regenerated inputs.
The original thirteen-control corpus is retained separately and identified in
the memo index. The original review finding remains part of the record.
