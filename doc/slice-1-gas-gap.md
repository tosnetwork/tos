# Slice 1 Stage 4 Gas Evidence — Gap Document

## 0. Status

**Status.** Active gap document, drafted 2026-04-30 on `actor-layer`.
This document is the explicit waiver attached to the `[ ] Gas
regressions are documented and within budget` checkbox in
[`doc/roadmap.md`](roadmap.md) §5. It is intentionally **not** a
declaration that the checkbox is closed; it is the precise statement
of what is closed today and what would be required to close the
remaining gap.

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
