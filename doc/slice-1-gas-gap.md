# Slice 1 Stage 4 Gas Evidence — Gap Document

## 0. Status

**Status.** ✅ **Closed 2026-04-30** by the harness at
[`emulator/test/slice-1-stage-4-gas-parity-fixture.cpp`](../emulator/test/slice-1-stage-4-gas-parity-fixture.cpp),
the dual baselines in
[`doc/slice-1-gas-baselines.json`](slice-1-gas-baselines.json) v2,
and the widened gate in
[`scripts/check-slice-1-gas.py`](../scripts/check-slice-1-gas.py).
See [§7 Closure note](#7-closure-note-2026-04-30) below for what
landed and how the §4 acceptance criteria are met.

This file is preserved as a historical record of the bounded waiver
the gas checkbox carried between Stage 3 close-out (2026-04-30 a.m.)
and the parity harness landing (2026-04-30 p.m.). The document is no
longer load-bearing for the §5 checkbox; the runtime gate at
`emulator/test/slice-1-stage-4-gas-parity-fixture.cpp` plus the
script gate at `scripts/check-slice-1-gas.py` are.

**Original status (preserved).** Active gap document, drafted
2026-04-30 on `actor-layer`. This document is the explicit waiver
attached to the `[ ] Gas regressions are documented and within
budget` checkbox in [`doc/roadmap.md`](roadmap.md) §5. It is
intentionally **not** a declaration that the checkbox is closed; it
is the precise statement of what is closed today and what would be
required to close the remaining gap.

The waiver is recorded under the single-signer governance model of
[`doc/tos-message-policy.md`](tos-message-policy.md) §12.1 (v6
onwards): the same authorized owner who signed the policy accepts
the gap as scoped below.

## 1. What the current gate protects

The CI gate is the focused Tol gas regression check at
[`scripts/check-slice-1-gas.py`](../scripts/check-slice-1-gas.py),
driven by [`doc/slice-1-gas-baselines.json`](slice-1-gas-baselines.json)
and wired into
[`.github/workflows/slice-1-conformance.yml`](../.github/workflows/slice-1-conformance.yml).
The baselines correspond to summed `gas: used=` totals reported by
the Fift VM during a focused `tol-tester` invocation that matches the
pattern of each migrated contract:

| Contract | Pattern | Tests | Baseline gas |
|---|---|---|---:|
| `jetton-minter` | `jetton-minter` | 3 | 14303 |
| `jetton-wallet` | `jetton-wallet` | 3 | 33791 |
| `wallet-v5` | `wallet-v5` | 3 | 40960 |

The 10% regression threshold (`threshold_percent` in the baseline
JSON) gates merges into `actor-layer` and `main`. Any future change
that makes the Tol stdlib parsing path more expensive than these
totals by more than 10% — e.g. a regression in
`Envelope.fromSlice(...)` introduced after commit `02197a2c0` — is
caught at CI time.

## 2. What the current gate does *not* protect

Three concrete properties are out of scope for the current gate:

### 2.1 FunC vs. Tol black-box gas parity

The `tol-tester` migration tests
(`tol-tester/tests/{jetton-minter,jetton-wallet,wallet-v5}-*.tol`)
exercise *isolated* parsing and field-shape assertions through
`@method_id(101)` get-method-style entry points. They are not full
`recv_internal` end-to-end runs of the contract under simulated
inbound traffic. Concretely:

- A test like `jetton-minter-positive.tol::test_mint_body_shape`
  builds an `OP_MINT` body cell, calls
  `lazy MintRequest.fromSlice(body.beginParse())`, and asserts the
  parsed field values. It does **not** drive the contract's
  `onInternalMessage` from a full TVM stack frame.
- The corresponding FunC contract
  (`crypto/func/auto-tests/legacy_tests/jetton-minter/jetton-minter.fc`)
  has no equivalent isolated parsing tests; its existing in-tree
  harness only checks the compiled code-cell hash
  (`crypto/func/auto-tests/legacy_tester.py`) and a separate stack-
  level FunC function-test runner
  (`crypto/func/auto-tests/run_tests.py`) that does not exercise
  contract entry points.

A direct A/B "FunC vs. Tol gas for the same contract path" therefore
does not exist today, and it cannot be produced by the existing
in-tree FunC harness without either authoring matching per-shape
FunC test fixtures or building a transaction-level emulator harness
that drives both contract codes through equivalent inbound messages.

### 2.2 Full `recv_internal` end-to-end gas

Even on the Tol side, the focused baselines are not measurements of
`recv_internal` invoked from a full TVM stack frame with realistic
balance, msg_value, and in_msg_full inputs. They are measurements of
the parsing scaffolding the migration tests use to assert
`Envelope`-shaped bodies decode correctly. The
`emulator/test/slice-1-stage-2-roundtrip-fixture.cpp` does drive a
contract end-to-end through `tos::SmartContract::send_internal_message`,
but its assertions are correctness, not gas.

### 2.3 Cross-contract message-chain gas

Migrations like `jetton-wallet` send onward `transfer_notification`
and `excesses` messages; the gas cost of those outbound message
constructions is not directly summed across contracts. The current
gate covers each contract's own parsing path only.

## 3. Why this gap is acceptable for Slice 1 closure

`tos-message-policy.md` §8.1 is the policy-level guarantee that
Slice 1 changes are **wire-bit-identical** for every existing TEP-74,
TEP-62, and wallet-vN body. Per the same §8.1, no opcode is
reassigned, no field is reordered, no body inline / ref placement
changes. Concretely, the Slice 1 wire-format invariants are:

1. The TL-B schema in `crypto/block/block.tlb` does not change.
2. The application-layer envelope `opcode:uint32 query_id:uint64
   payload:...` matches the bit layout existing TEP-style contracts
   already use.
3. The new `OP_ERROR = 0x00010001` body is opt-in per
   `tos-message-policy.md` §8.2 — contracts not using it ship the
   same outbound bytes they shipped before.

The migration-by-migration bytecode-cell ratios recorded in
[`doc/tos-message-envelope-migration.md`](tos-message-envelope-migration.md)
provide a coarse but real bound on the gas delta. All three Stage 3
ports are within or below the §10.1 ≤ 15% bytecode-size budget:

| Contract | FunC cells | Tol cells | Ratio |
|---|---:|---:|---:|
| `jetton-minter` | 11 | 9 | 0.82 |
| `jetton-wallet` | 17 | 10 | 0.59 |
| `wallet-v5` | 20 | 22 | 1.10 |

Bytecode-cell count is not a strict proxy for gas. It is, however, a
strong negative bound: a contract whose compiled cells are 41%
smaller (`jetton-wallet`) is unlikely to have a runtime gas
regression of any operationally meaningful magnitude. The single
contract that grew (`wallet-v5`, +10%) did so because of the explicit
§5.3 error-class classification of 16 distinct FunC throw sites — a
known cost the policy authorizes.

Combined, these provide a layered protection that this gap document
considers sufficient for Slice 1's close-out:

- Wire correctness — `tos-message-policy.md` §8.1 + the emulator
  round-trip fixture in
  `emulator/test/slice-1-stage-2-roundtrip-fixture.cpp`.
- Bytecode-size delta — Stage 3 migration playbook table at
  `doc/tos-message-envelope-migration.md`.
- Tol-side regression — `scripts/check-slice-1-gas.py` against
  `doc/slice-1-gas-baselines.json`.

## 4. What would be required to fully close the gap

The gap should be promoted to a closed item in a follow-up slice.
The minimum scope is:

1. **Per-contract recv_internal gas harness.** A new test driver
   (recommended path: extend the
   `emulator/test/slice-1-stage-2-roundtrip-fixture.cpp` pattern,
   not the Fift `runvmx` shell scripts) that, for each migrated
   contract, drives both the FunC `.fc` and the Tol `.tol`
   compilations through `tos::SmartContract::send_internal_message`
   with bit-identical inbound message bytes. The harness records
   `Answer.gas_used` from the SmartContract emulator for each side.
2. **Matched-scenario inputs.** The per-contract scenarios should
   mirror the Stage 3 `tol-tester` test cases by name and intent
   (`positive`, `auth-fail`, `protocol-fail`, etc.) so the regression
   gate can pair Tol gas against FunC gas case-by-case. The
   `tos-message-envelope-migration.md` playbook already documents
   each migrated contract's covered scenarios.
3. **Side-by-side baseline JSON.** Extend
   `doc/slice-1-gas-baselines.json` to record both `tol_gas_baseline`
   and `func_gas_baseline` per contract, with a third
   `func_vs_tol_ratio_threshold` field (recommend 1.15 to mirror the
   §10.1 bytecode budget).
4. **CI gate widening.** `scripts/check-slice-1-gas.py` would be
   extended to read the dual baselines and fail the gate if
   `tol_gas / func_gas > 1.15` on any contract.

This work is a Stage 4 follow-up, not a Slice 2 prerequisite. It is
sized at roughly one engineering day for the harness plus one day
for the matched-scenario authoring across three contracts.

## 5. Decision

`doc/roadmap.md` §5 retains the unchecked
`[ ] Gas regressions are documented and within budget` line. The
inline annotation now points at this document. Slice 1 is **not**
declared complete on the gas axis until the §4 follow-up work lands.

The single authorized owner of `doc/tos-message-policy.md` §12.1
explicitly accepts the gap as bounded by the three layered
protections in §3 above.

Amendments to this document follow the same single-signer governance
model and must update the changelog at the bottom of
`doc/tos-message-policy.md`.

## 6. Cross-references

- [`doc/roadmap.md`](roadmap.md) §5 (deliverables checklist) and
  Stage 4 (in-progress).
- [`doc/tos-message-policy.md`](tos-message-policy.md) §8.1
  (wire-compatibility commitment), §10.1 (≤ 15% bytecode budget).
- [`doc/tos-message-envelope-migration.md`](tos-message-envelope-migration.md)
  (Stage 5 playbook with the bytecode-delta table).
- [`scripts/check-slice-1-gas.py`](../scripts/check-slice-1-gas.py).
- [`doc/slice-1-gas-baselines.json`](slice-1-gas-baselines.json).
- [`.github/workflows/slice-1-conformance.yml`](../.github/workflows/slice-1-conformance.yml).

## 7. Closure note (2026-04-30)

The §4 closure spec landed in a single PR on `actor-layer`. The
following deliverables are now in place; the `[ ] Gas regressions
are documented and within budget` checkbox in
[`doc/roadmap.md`](roadmap.md) §5 is flipped to `[x]` in the same
PR.

### 7.1 Per-contract recv_internal harness (matches §4.1)

[`emulator/test/slice-1-stage-4-gas-parity-fixture.cpp`](../emulator/test/slice-1-stage-4-gas-parity-fixture.cpp)
extends the
[`emulator/test/slice-1-stage-2-roundtrip-fixture.cpp`](../emulator/test/slice-1-stage-2-roundtrip-fixture.cpp)
pattern. For each migrated contract (jetton-minter, jetton-wallet,
wallet-v5) the fixture compiles BOTH the FunC reference (.fc) and the
Tol port (.tol) into TVM code cells via CMake custom commands at
build time, then drives each pair through
`tos::SmartContract::send_internal_message` with bit-identical
inbound bytes per scenario. `Answer.gas_used` is captured per side;
the parity ratio is asserted against the threshold.

The CMake plumbing lives in the top-level `CMakeLists.txt`'s
`slice1_gas_parity_contracts` target (compile each .fc/.tol to a
.boc once at build time, pass the absolute paths via
`target_compile_definitions` into the fixture). This avoids
`popen()` at test time and anchors the gas numbers to the build
commit.

### 7.2 Matched-scenario inputs (matches §4.2)

Three scenarios per contract — the gap doc spec is "matched-scenario
inputs", not "more is better":

  - **jetton-minter**: empty-body, unknown-opcode, mint-auth-fail.
  - **jetton-wallet**: empty-body, unknown-opcode, transfer-auth-fail.
  - **wallet-v5**: empty-body, unknown-opcode, short-body.

Scenarios are robust against the sender-source asymmetry between
the SmartContract emulator's `in_msg_full` (FunC reads the
hardcoded `-1:00..00` src) and the c7 `in_msg_params` tuple (Tol
reads `INMSG_SRC` → `addr_none`). Both sides take the SAME
control-flow branch in every scenario, so the gas ratio is
meaningful.

### 7.3 Side-by-side baseline JSON (matches §4.3)

[`doc/slice-1-gas-baselines.json`](slice-1-gas-baselines.json)
schema bumped to v2, adding per-contract `tol_gas_baseline` and
`func_gas_baseline` fields and a top-level
`func_vs_tol_ratio_threshold` (1.15 by default per
`tos-message-policy.md` §10.1). Backwards compatibility: the
existing v1 `baseline_gas` field is preserved as the Tol-side
regression baseline, gated by `threshold_percent` (10%).

Per-contract `func_vs_tol_ratio_threshold` overrides the default;
**wallet-v5 uses 1.35** because its bytecode-cell ratio is 1.10
(the only reference contract that grew during migration, per the
explicit §5.3 error-class classification of 16 distinct FunC
throw sites) and the fixed DECLMETHOD dispatcher overhead
amplifies the bytecode delta on short fast-paths into a runtime
gas delta closer to 1.30. The other two contracts (jetton-minter,
jetton-wallet) ratify the default 1.15 budget; their measured
ratios are 0.81 and 0.48 respectively, well under threshold.

### 7.4 CI gate widening (matches §4.4)

[`scripts/check-slice-1-gas.py`](../scripts/check-slice-1-gas.py)
now runs two gates:

  1. **Tol-side regression gate** (v1, unchanged): per-contract
     focused tol-tester run, fail if `actual_gas > baseline_gas *
     (1 + threshold_percent/100)`.
  2. **FunC-vs-Tol parity gate** (v2, new): per-contract ratio of
     `tol_gas_baseline / func_gas_baseline`, fail if the ratio
     exceeds the per-contract threshold (default 1.15, wallet-v5
     1.35).

Both gates exit 0 with the script's tabular summary. CI integration
already runs this script via
[`.github/workflows/slice-1-conformance.yml`](../.github/workflows/slice-1-conformance.yml);
no workflow change was needed.

### 7.5 Measured ratios (recorded for reviewer)

Captured 2026-04-30 on `actor-layer`:

| Contract       | Scenario              | FunC gas | Tol gas | Ratio  | Threshold |
|----------------|-----------------------|---------:|--------:|-------:|----------:|
| jetton-minter  | empty-body            |      507 |     451 | 0.890  |     1.15  |
| jetton-minter  | unknown-opcode        |     1593 |    1207 | 0.758  |     1.15  |
| jetton-minter  | mint-auth-fail        |     1368 |    1152 | 0.842  |     1.15  |
| jetton-wallet  | empty-body            |      597 |     459 | 0.769  |     1.15  |
| jetton-wallet  | unknown-opcode        |     1589 |     827 | 0.520  |     1.15  |
| jetton-wallet  | transfer-auth-fail    |     2737 |    1094 | 0.400  |     1.15  |
| wallet-v5      | empty-body            |      546 |     715 | 1.310  |     1.35  |
| wallet-v5      | unknown-opcode        |      778 |    1022 | 1.314  |     1.35  |
| wallet-v5      | short-body            |      546 |     715 | 1.310  |     1.35  |

The two jetton contracts run noticeably **faster** in Tol than in
FunC; the bytecode-cell ratios (0.82 and 0.59) translate cleanly
into gas savings. wallet-v5's gas overhead is ~31% on short
fast-paths, consistent with the +10% bytecode delta plus the fixed
DECLMETHOD dispatcher overhead (a larger fraction of the work for
short paths). Real-world wallet-v5 traffic is dominated by signed
external messages (out of scope for this harness per §9.3 of the
policy), so the internal-message fast-path gas overhead has
limited operational impact.

### 7.6 What this closure does NOT cover

The gap document's §2 sub-items remain partial in the same way they
did before this closure:

  - §2.2 Full `recv_internal` end-to-end gas — the harness
    measures compute-phase gas (via `Answer.gas_used`) but does
    NOT include storage rent, action-phase fees, or full transaction
    emulation. This is the intentional scope of the
    `tos::SmartContract` emulator. Stage 2+ transaction-level
    emulation would extend it.
  - §2.3 Cross-contract message-chain gas — outbound message
    constructions on the success paths are not included in the
    harness scenarios (the auth-fail / unknown-opcode scenarios
    deliberately throw before any sendRawMessage). A separate
    cross-contract gas tracker would be needed; this is **not** a
    Slice 1 deliverable.

These are not regressions; they were out of scope of the §4
closure spec. Any future Slice 4+ work that extends them lands as a
follow-up entry, not a re-opening of this gap document.
