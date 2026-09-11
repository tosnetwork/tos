# D76 x/b anchors: independent shadow-build review

B, 2026-09-11. Reviewed A commit
`09a94d798ea9b9b7c68f10a128c00de817d89141` against the coordinator's stated
specification version: memo `7a732682`, SHA256 prefix `e83e56b5e8fb08d9`.
This is post-implementation review, not a frozen prediction. A's files were
not edited. All mutations/build products were isolated under `/tmp`.

**Result: both requested equalities carry enforcement at their tested
boundaries. Principal-only callers also demonstrably retain fee_budget.**
No deviation was found in those checks. Full prepare/Failed acceptance is not
claimed, and no guard is retired.

## Principal equality

`transaction.cpp:4736–4737` compares the decoded serialized Native message's
complete CurrencyCollection with the independently supplied authorized x and
returns -7200 `Native payout value differs from authenticated exact x`.
It is independent of q equality (`:4738–4739`) and precedes returning the pair.

The unchanged real Native fixture sends **137**, pays **100**, declares exact
q=100 and uses legacy ceiling zero. Declared x=136/138 each returns precisely
the principal-equality -7200, not an earlier send/pricing error. x=137 passes.

In a shadow build B removed **only** the two-line principal comparison and its
error return, keeping serialization, Native pricing/debits and q equality.
Both mismatch calls then construct successfully. The unchanged tests fail at
`result.is_error()`: exit **1**, test lines **8101** and **8109**, respectively.
Restoring the comparison restores both expected rejections, exit 0 for each
checking test. This is rejection at the intended boundary, not proof that a
more upstream failure happened to reject these inputs.

Observation/execution scope: actual Native pair construction and returned
status. This is not a signed-candidate mutation through the live collator.

## Reserve equality

`workchain-m3-business-config.h:24–29` distinguishes missing configuration
(-7201 `ConfigInvalid: explicit max_bounce_cost absent`) from unequal b
(-7200 `Withdrawal reserve differs from authenticated max_bounce_cost`).
The latter equality is reached from the actual registered proof_work hook
(`workchain-m3-node-engine.h:150`), execution entry (`:250`) and a freshly
decoded constructed W record (`:297–302`). Configuration resolution also
rejects absence before accepting a prepare profile (`:125–126`).

B independently resolved the real fixture configuration through
`WorkchainExecutionRegistry::resolve_scoped_workchain` and called its
registered executor's `proof_work`, using the actual candidate BOC. The
configuration and unchanged candidate both carry **23**. Encoding and
resolution remain active; this is not a detached call to the reserve helper.

| Variant | b=23 | b=22 | b=24 |
|---|---|---|---|
| Original | admitted by hook | exact -7200 reserve equality | exact -7200 reserve equality |
| Only reserve inequality rejection removed | admitted by hook | wrongly admitted by hook; probe CHECK | wrongly admitted by hook; probe CHECK |
| Restored | admitted by hook | exact -7200 reserve equality | exact -7200 reserve equality |

The removal preserves the missing-config branch, the real registry/config
resolver, fee check and proof-shape work. Both mutant probes fail specifically
at `CHECK(result.is_error())`, `reserve.cpp:20`, with **SIGABRT** (Python
returncode **-6**, conventionally shell exit 134). No other diagnostic is
counted as the expected rejection. Both restored checking invocations exit 0.

**Limit:** this hook intentionally precedes cryptographic verification. The
b-mutated candidates retain the old proof bytes; neither B nor A claims those
are matching proofs. No premise here relies on an invalid proof passing a
kernel. Execution-entry and post-encoding W checks were inspected, but this
review did not independently inject an erroneous stored reserve after the
initial admission gate or run a new live W publication. Missing-configuration
behavior was inspected, not counted as a new independent positive/negative test.

Fixture: `/tmp/uno-m3-live-ec7zmf8s`. Its zerostate SHA256 is
`e3a2dbd75f941bc202d9f3b1285cce596ff2657aa61b979cdf83d9a2a18e3e4f`;
candidate SHA256 is
`1535edfe02bb8d2506fb53b46ecc92caab1e335c2b8e836262cd28a2c1f619c0`.
23 is decoded from this explicit test configuration, never a local default.

## Principal-only pricing budget: behavioral control

The pricing expression at `transaction.cpp:4664–4665` remains:

```
exact_outward_fee ? custody.balance.tomis : fee_budget
```

B added an isolated test using the same real fixture and actual Native fee 100:

| Call | Observed result |
|---|---|
| Neither anchor, ceiling 0 or 99 | pricing refusal `batch native message send failed` |
| Only x=137, ceiling 0 or 99 | same refusal, matching both legacy code and message |
| Only x=137, ceiling 100 | success |
| x=137 and q=100, ceiling 0 | success |

Thus principal-only does not accidentally get the whole custody pricing
ceiling, and sufficient legacy budget still works. The early pricing refusal
is **the intended observation for this budget control**; it is not reused as
evidence for either -7200 equality control.

To show the control is live, B changed only the selector to
`(exact_outward_fee || exact_principal) ? custody.balance.tomis : fee_budget`.
The new test then fails at `principal_only.is_error()` (shadow line **10984**),
exit **1**: a principal-only call incorrectly succeeds with zero fee_budget.
Restoring the original selector restores all four rows. The new control is
retained as an isolated `.inc` artifact; it is **not yet included in default
CTest**. A must integrate it into the owned Native test translation unit before
it can be described as a continuously enforced regression guard. Existing q-only
99/101 controls were also rerun on the restored build and still reach their
own exact-fee -7200, confirming that the two optional anchors remain separate.

## Source-to-anchor chain and remaining scope

Read-only direct-reference inventory found one assignment to payout_principal:
`workchain-m3-node-engine.h:306`, from the verified operation's principal.
It travels through local WorkchainAccountEffects (`workchain-account-engine.h:79`),
settlement (`workchain-account-settlement.h:357`), and payout overlay (`:138`)
to the builder. No claimant-supplied effects decoder assignment was found.
This is a lexical/direct-call inventory, not exclusion of every alias or
indirect runtime coupling. Removal of an upstream forwarding assignment was
not tested here; the x mutations target the final Native equality.

Evidence, exact mutation patches, the budget control and standalone registered
reserve probe are in
[the evidence directory](measurements/uno-m5-d76-independent/).
All normal, removed and restored results are retained, with a SHA256 manifest.

Build method: export the pinned crypto/block and crypto/test source; rebuild
explicit shadow transaction/test objects and link existing native libraries.
The reserve probe replaces the test main and uses the real registry/executor;
its unused execution backend is the real linked backend, not a success stub.
This was not a hermetic rebuild of every dependency. Scope remains the Native
pair boundary and registered pre-proof reserve hook, not the full materialized
arena, accepted-block reconstruction or custody Failed publication.

The original independent anchor table is superseded for x/b implementation by
this review. The f matching-proof evidence remains in its separate report.
Four anchored components do not imply all nine prepare contract items are done.
