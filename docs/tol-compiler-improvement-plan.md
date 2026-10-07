# TOL compiler diagnostic improvement plan

Status: proposed implementation work. This document defines evidence, scope, and acceptance criteria; it does not implement compiler changes or claim measured benefits from the proposed fixes.

The relevant parser, query-correlation recognizer, and assembler mechanisms were checked against main commit `9960de239fda55dd9888cd23893bd694af130e44`. The original experiment used `334be6e51de84236449a9009196ad680b59aa7da` (TOL 1.3.0). The observations below are historical results from that pinned experiment; no new runtime experiment on current main is claimed.

## Priorities

| Priority | ID | Proposed work | Evidence | Delivery boundary |
| --- | --- | --- | --- | --- |
| P0 | — | None justified by the observed cases | No demonstrated original-contract security defect requiring an emergency compiler change | Do not invent a P0 item |
| P1 | C01 | Explain and offer a narrowly scoped fix for `get fun` combined with an explicit method ID | Six initial submissions rejected with the same declaration diagnostic | Parser diagnostic and regression tests |
| P2 | C02 | Avoid inferring a query ID from an unrelated later 64-bit field; distinguish uncertainty from proven omission | Two actual warnings misidentified an amount field | Query-correlation analysis and warning sensitivity tests |
| P2 | C03 | Consider an opt-in advisory for raw instruction-byte insertion when a symbolic opcode exists | A post-budget mutant failed assembly; replacing only its raw opcode with the symbolic spelling assembled | Small lint or documentation/tooling change, with a capacity-boundary control |

Implement C01 first. C02 is a separate correctness/precision change to an existing warning. C03 needs a small design decision about whether a compiler lint or documentation/tooling guidance is the better home. These priorities are engineering judgments grounded in observed cases, not measured reductions in future repair cost.

## C01 — actionable fixed-method-ID diagnostics

### Problem and evidence

Six initial TOL submissions (tasks 01, 02, 04, 05, 07, and 09) combined `@method_id(100001)` with `get fun`. All failed in the frontend with:

```text
@method_id can be specified only for regular functions
```

The fixed task ABI required method ID 100001. Other independently generated TOL submissions used an ordinary `fun` with the same annotation and successfully executed the getter by numeric ID. This is an invalid declaration combination, not a missing getter capability or a security vulnerability.

Minimal declaration illustrating the rejected combination:

```tol
@method_id(100001)
get fun get_state(): int {
    return 0;
}
```

For an eligible top-level function, the intended fixed-ID-preserving form is:

```tol
@method_id(100001)
fun get_state(): int {
    return 0;
}
```

These snippets illustrate the declaration; integrate them into a complete compiler-test fixture with an entrypoint for compilation and numeric getter execution.

### Proposed change

Specialize the diagnostic when `get fun` is the reason for rejection. Explain the ordinary getter form and the explicit-method-ID regular-function form. Where existing diagnostic infrastructure supports it, provide a machine-readable hint/fix-it that removes only the inappropriate `get` modifier.

Do not remove `@method_id` when the caller requires a numeric ABI. Do not blindly apply the same edit to contract-block getters, generic functions, methods, entrypoints, or functions with mutate/self parameters. Preserve all existing prohibited combinations.

Implementation entry point: [annotation validation](../tol/ast-from-tokens.cpp), currently around lines 1803–1805.

### Acceptance criteria

- [ ] Reproduce the declaration rejection before the change; assert the cause-specific diagnostic afterward.
- [ ] Cover all six observed declaration patterns, without counting them as six distinct compiler bugs.
- [ ] Compile the eligible replacement and execute getter 100001; assert the return value.
- [ ] Keep rejecting other prohibited annotation combinations with accurate messages.
- [ ] Verify that contract-block getters and multiply-invalid declarations receive no unsafe automatic rewrite.
- [ ] Record whether the implementation supplies text only or a structured fix-it. Do not claim reduced AI repair rounds without a separate generation study.

## C02 — query-ID inference and warning precision

### Problem and evidence

The task-08 message layout was:

```text
opcode:u32, seq:u32, valid_until:u32,
destination_workchain:i8, destination:u256, amount:u64
```

It has no query-ID field. Its specified outgoing body is `opcode:u32, seq:u32`. The compiler nevertheless emitted:

```text
reply does not propagate inbound `queryId`
```

The initial contract passed all 25 frozen cases. Task 06 independently exhibited the same inference problem with `opcode:u32, seq:u32, amount:u64`; its send occurred in a helper, while a function-local warning claimed there was no reply. That candidate passed its 23 frozen cases. Passing those cases does not prove general security, but the specified layouts establish that the amount field is not a query ID.

In [the query-ID pass](../tol/pipe-check-query-id-propagation.cpp), the recognizer sets `manual_opcode_loaded` on a 32-bit load and then binds a later 64-bit load as `inbound_query_id_local`. Intervening consumption does not invalidate the match. Raw sends can also be classified as unproven propagation, while the emitted wording states non-propagation as a fact.

### Proposed change

Tighten or invalidate manual-layout inference after intervening consumption. Treat the `opcode:u32, queryId:u64` adjacency pattern as evidence only within a documented heuristic; adjacency alone is not proof of a protocol's field meaning. Preserve stronger evidence from typed envelopes or explicit correlation APIs where available.

Distinguish an identified correlation field whose propagation is demonstrably absent from a raw/helper send whose propagation cannot be proved. Avoid automatically inserting `disclaim_query_id()` just to silence an incorrect inference. Whole-program helper analysis is optional and should not become an implicit scope expansion.

### Acceptance criteria

- [ ] Preserve fixtures that reproduce both original amount-as-query-ID warnings before the fix.
- [ ] Ensure neither task-06 nor task-08 layout identifies `amount` as `queryId` afterward.
- [ ] Cover intervening loads, skips, aliases and unsupported parser operations; unknown cases must not become confident claims.
- [ ] Keep a genuine `opcode:u32, queryId:u64` missing-propagation case diagnostic-positive.
- [ ] Retain typed-envelope checks and independent receiver scopes.
- [ ] Show warning sensitivity by removing real propagation from a previously valid reply and observing the expected warning.
- [ ] Exercise raw sends and helper sends; assert uncertainty wording where propagation is unresolved.
- [ ] Keep diagnostic counts distinct from compile failures and runtime security defects.

## C03 — raw instruction bytes and assembler capacity

### Problem and evidence

The original task-10 TOL contract compiled and passed its PQ tests. It included:

```tol
asm "x{F93100} s,"
```

A post-budget mutation that removed only its outer-body shape guard changed code placement. The frontend succeeded, but Fift rejected the generated output with:

```text
s,:slice does not fit into cell
```

A controlled variant changed only that asm string to:

```tol
asm "PQCHECKSIG_MLDSA44"
```

It passed both frontend and assembly. This was an assembly-capacity problem exposed by surrounding layout, not compiler-enforced authorization or an observed signature-verification defect. The original task remains a first-attempt success.

[Asm.fif](../crypto/fift/lib/Asm.fif) routes symbolic opcode definitions through `@addop` / `@ensurebitrefs`. Bare `s,` inserts bytes without that continuation-capacity handling.

### Proposed change and decision

Choose a small, opt-in advisory for known raw opcode spellings, or initially improve symbolic-opcode discoverability in documentation/tooling. Suggest the existing symbolic instruction or appropriate stdlib wrapper. Do not prohibit arbitrary raw asm, automatically rewrite arbitrary Fift, or claim that a spelling warning establishes stack or security semantics.

### Acceptance criteria

- [ ] Retain a deterministic capacity-boundary fixture with raw frontend success and assembly failure.
- [ ] Show that replacing only the opcode spelling with the symbolic form assembles.
- [ ] Execute an equivalent valid case and check behavior, rather than treating assembly as sufficient validation.
- [ ] Exercise a non-boundary control so the advisory does not imply every raw-byte program fails.
- [ ] If shipping a lint, define its recognized patterns, severity, opt-in behavior, and explicit acknowledgement mechanism.
- [ ] Keep the historical assembly rejection separate from original participant compile failures and security-defect counts.

## Existing behavior to retain: `uint64` and `coins`

Two additional type errors in tasks 04 and 07 were already present in initial source but became visible only after the getter declaration was repaired:

```text
can not pass `uint64` to `coins`
```

The existing diagnostic provides an `as coins` hint. Keep this type check; do not add an implicit conversion to improve a benchmark score. A repair must preserve the fixed-width storage ABI while using the required argument type for `storeCoins`. Tests must still verify outgoing value, fees and authorization. No new compiler feature is requested for these two errors.

## Upstream comparison

The source comparison used the official upstream snapshot `ed629c416f7a03cd3838697fcee9f8cd0097700b`, labelled Tolk 1.5.0, on 2026-10-06. This was a source audit, not an upstream execution of the TOS experiment.

| Item | Source-audit finding | Implication |
| --- | --- | --- |
| C01 | The upstream parser has the same rejection text and getter/explicit-ID restriction | The diagnostic improvement is relevant upstream too |
| C02 | The upstream compiler snapshot has no matching propagation pass/recognizer; TOL's pass explicitly implements TOS message policy | Fix this TOL-specific warning; do not claim upstream has the same false positive |
| C03 | The upstream assembler shares the size-aware symbolic-opcode mechanism | The raw-insertion hazard is general, but this TOS PQ case was not reproduced upstream |
| `uint64` / `coins` | The upstream assignment rules and `storeCoins` signature likewise distinguish these types | Retain the existing type check |

Pinned comparison sources:

- [Parser restriction](https://github.com/ton-blockchain/ton/blob/ed629c416f7a03cd3838697fcee9f8cd0097700b/tolk/ast-from-tokens.cpp#L1869-L1872)
- [Compiler pipeline](https://github.com/ton-blockchain/ton/blob/ed629c416f7a03cd3838697fcee9f8cd0097700b/tolk/tolk.cpp)
- [Assembler capacity handling](https://github.com/ton-blockchain/ton/blob/ed629c416f7a03cd3838697fcee9f8cd0097700b/crypto/fift/lib/Asm.fif#L64-L73)
- [Coins assignment rules](https://github.com/ton-blockchain/ton/blob/ed629c416f7a03cd3838697fcee9f8cd0097700b/tolk/type-system.cpp#L818-L829)

## Evidence provenance and limits

The local experiment branch is `experiment/ai-contract-language-20261005`, with completed evidence at commit `93bd6935e22a05223a5199d7c85dd3c7bc537483`. That experiment branch and its full raw logs are not published by this documentation PR. Request the retained evidence from the experiment owner when independently auditing the historical measurements; a commit ID alone does not provide public access.

Evidence locations within that retained checkout:

| Observation | Retained artifact |
| --- | --- |
| Six C01 diagnostics | `experiments/ai-contract-language/contracts/task-{01,02,04,05,07,09}/tol/round-00/frontend.stderr` |
| C02 warnings and sealed source | `experiments/ai-contract-language/contracts/task-{06,08}/tol/round-00/` |
| C03 assembly rejection | `experiments/ai-contract-language/mutations/task-10/run-01/tol-outer-shape/result.json` |
| C03 single-change symbolic control | `experiments/ai-contract-language/supplementary/pq-raw-layout-run-01/results.json` |
| C04 latent type diagnostics | `experiments/ai-contract-language/contracts/task-{04,07}/tol/round-01/frontend.stderr` |

The cohort had one model/configuration, ten purposive paired tasks, a fixed ABI and documented tool/context limitations. Six instances of C01 are one error category, not six compiler defects. Both original PQ implementations passed their first attempts. Typed PQ keys/signatures, a new byte-chain abstraction, target-version checking and expensive-operation metadata are therefore not required changes justified by this sample. They remain separate research proposals requiring their own evidence.

Implementation PRs should include narrowly scoped red/green regression receipts and applicable native execution. The present change is documentation-only: validate Markdown structure, relative links and whitespace. It does not require a compiler rebuild and does not claim that any future acceptance checkbox has already passed.
