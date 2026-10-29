# Self-pay simulation C ABI author self-check

This self-check accompanies the prototype C ABI commit after the isolated typed
error refactor `25219036d8709436d8de1b5d550f66832fc15c6b`. The earlier exact
`8a76b00d4` acceptance covers only the prior main integration and native tests.
This increment is not complete R02 or mobile delivery and has no merge-ready PR.

## Boundaries and callers

Applicable checklist areas: upstream comparison, cryptographic authorization,
proof/codec correctness, determinism, memory/resource lifetime, native build and
FFI, privacy, tests/evidence and documentation. No consensus rule, contract,
signing key store, transport, persistence or broadcast path is modified.

A search of lite-client and native tests finds the new C entry point only in
`embedded.h`, its implementation and the actual ctypes test. Swift/JNI consumers
do not call it. `render_self_pay_simulation` is called by the C entry point and
its explicit synthetic formatter test. Message binding is shared by the one-shot
proof path and prepared executor; it validates bounded complete external-in
structure and the exact destination before classifying unsupported profiles.
The public message bytes/root hashes are distinct. No signature bypass parameter
exists. The reused native engine still performs real PQ verification.

The account/configuration error enums overlap numerically and are explicitly
mapped at their own stages into a separate simulation domain. Native -701 is
import rejection, not a general insufficient-balance diagnosis. Other unknown
execution, serialization and codec failures are internal errors, not unsupported.
Only a successful codec produces an executed transaction. Unaccepted messages
have a real VM exit code and no transaction. Unsupported results include only
actually available observations/context/seed; nonexistent accounts explicitly
have observed balance0 and no invented Account cell hash. An actual authenticated
absence case exposed the old read model's empty balance, which the new renderer
initially misclassified as internal; the correction is covered by the import
corpus and preserves the old read model.

The C ABI consumes a same-anchor persisted live state, including an explicit
anchor-only initial state. Missing state is not an initialization/reset API.
All successful tagged estimates carry a separate next-state; callers must commit
it before consuming the estimate. This API neither persists nor broadcasts and
never releases an outbox slot or authorizes another signature. The result has a
new interface/local_estimate scope; it cannot be decoded as a verified receipt or
written into the authenticated balance/authority cache. Current monetary values
are canonical decimal strings produced by native TL-B/uint64 types. No financial
arithmetic was introduced; total_fees is not treated as full sending cost.

The mechanism is a local fixed PQ wallet extension, absent from the previously
checked local upstream proof surface. It reuses transaction execution rather
than changing VM/opcode/fee rules. The shared wallet BOC preflight now reports a
typed resource code for its unchanged byte/cell/depth limits; the old transaction
C ABI still maps refusals to its original return codes. Its regression runs.

## Resources, privacy and output publication

There is no added cache, handle, map, actor, timer, file descriptor, socket, thread
or production file. Per-call state is released on every return. The C ABI first
checks all input lengths, kinds, duplicate singleton/count limits and a single
64MiB decreasing budget including JSON, prior state and message. Each JSON/state
and exact message is at most1MiB; account/config replies at most16MiB. Account
BOC preflight precedes proof cell allocation and material copies. The account,
configuration and message graph bounds remain enforced; preparation may parse
again and clone immutable backing buffers, whose peak belongs in mobile tests.
The actual aggregate-budget test exceeds the total with individually bounded
parts and must refuse before material copying.

Rendering uses a fixed2MiB buffer and non-growing StringBuilder. The synthetic
formatter test fills it past the bound; a growable variant must fail that test.
Its synthetic observations are not authentication evidence. The next-state
renderer handles only three fixed block identities/timestamps, not endpoint-sized
containers. Caller result capacity is at most2MiB, state capacity1MiB. These are
candidate limits, not accepted phone memory budgets. The C ABI contract requires
valid pointer ranges and output/length slots disjoint from every borrowed input.
Invalid output pointers/capacities cannot safely be cleared. With valid outputs,
all subsequent failures clear both buffers and lengths; both bounded renderings
and capacities are checked before either result is published.

No original message/transaction BOC, body, private key, signature or VM tail is
returned. The nested transaction codec includes only its existing structured
phases, hashes, values and addresses. The new schema closes each object's field
set; decimal-pattern constraints do not substitute for native integer ranges.
Privacy and schema tests reject injected forbidden fields. Status text/reasons
are fixed; free-form native errors are not serialized.

## Evidence and incomplete gates

The retained fresh mobile-profile CMake build exercises real native sources and
the shared-library C ABI, not a Python facsimile. Local relevant CTests, exact
named cases, pinned-schema positives/negatives and source variants are indexed
in the companion memo. Each control is an out-of-tree compiled copy; no product
fault hook is present. Initial control tooling confused a dylib's own LC_ID with
a dependency and then applied link-only hidden visibility while compiling its
variant. Those failed attempts were retained. Corrected tooling compiles an
object with its actual compile flags, links static dependencies and audits
LC_LOAD commands, so it does not silently execute an old proof dylib.

Controls remove each result/state/length clearing guard and exact-byte binding,
inject a private-tail field and remove total input accounting. Separate models
force a zero digest (-6) and codec failure (-4), then show that swallowing the
codec failure as unsupported is detected. The zero-seed prepared-execution test
was updated to expect typed Context and its guard-removal still fails. None of
these source-fault models is claimed to be a natural hash preimage or network
input reaching an impossible internal state.

Node capture tools remain explicitly f2d while the adapter is this candidate.
The active and absent public corpora were captured from fresh isolated VM16
networks with cleanup receipts and no broadcast. The existing VM18 Elector
corpus is an unsupported-profile replay, not a basechain payment test. Public
hexadecimal11 fixture signing material is not a real wallet secret; private
runtime files and databases remain outside Git. Only bounded required inputs,
schemas/tests and result/hash indexes are committed.

Still incomplete: the explicit simulation-purpose acquisition/C ABI, full
version/deployment/RESCUE/boundary matrix, Apple/Android builds and exports,
worst legitimate/adversarial phone resource and concurrency acceptance, ASAN/UBSAN,
final gas-margin/fee/send-max rules, outbox, phone signing/payment, backup/cold
recovery/migration, hosted relevant CI and final independent/third-party gates.
No skipped/unrun gate is counted as passed. The old proof/read/getter interfaces
remain intact; public acquisition must be added without fake getter requests.
