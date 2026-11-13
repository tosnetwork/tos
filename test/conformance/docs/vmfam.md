# Migrated VM families (`vm` harness)

Every VM-level vector family of the tos tree, and the VM families of the RTOS tree, as `vm` fixtures.
Contexts come from the families' own scenario generators or data files; every effect was filled by
the C++ reference (`conformance.py create`). The `vm` harness contract is unchanged.

Converters: `migrate/vmfam.py` (tos families), `migrate/vmfam_rtos.py` (RTOS families) with
`migrate/vmfam_rtos_asm.rs`, a code-cell builder compiled against an RTOS tree, which builds each
code cell, and each library collection, with the RTOS assembler and cell library the way the RTOS
test does.

## tos families

| Family | Fixtures | Context source | Checked against |
|---|---:|---|---|
| `vm-prefix` | 1,264 | `vm_prefix_scenarios.py` (truncated, unassigned, version-gated prefixes; opcode table from `test-vm-opcode-table`) | `test-vm-endstate` |
| `vm-ext` | 341 | `vm_ext_scenarios.py` | `test-vm-endstate` |
| `vm-family` | 16,629 | `vm_family_scenarios.py`, every family but `fuzz` | `test-vm-endstate` |
| `vm-closure-fuzz` | 2,000 | `vm_closure_fuzz.py`, the frozen seed set 1..5 × 400 (also the `fuzz` family of `vm_family_scenarios.py`) | `test-vm-endstate` |
| `vm-varuint` | 28 | `vm_varuint_scenarios.py --write` | `test-vm-endstate`; `--check` authored rules |
| `vm-library` | 10 | `vm_library_scenarios.py`, with its library collection | `test-vm-endstate` with the collection; `--check-native` authored effects |
| `pq-suite-parity` | 143 | `suite-scenarios.tsv` | `test-pq-suite-parity`, `suite-expected.tsv` |
| `pq-version` | 80 | `version_scenarios.py` | `test-pq-suite-parity` |
| `pq-v16-parity` | 330 | `test/pq-readiness/scenarios.py` on `test/pq-mldsa44/prepare_vectors.py` vectors, with the func and tol bindings | `test-pq-v16-parity` |
| `pq-falcon512-parity` | 161 | `test/pq-falcon512/prepare.py`, `compile_probes.py`, `exotic.py` | `test-pq-falcon512-parity` |
| `native-cost` | 12 | `probe_native_cost.py` (fresh keys each run; this scenario set is frozen) | `test-fee-native-cost` |

`vm-prefix`, `vm-ext`, `vm-family` and `vm-closure-fuzz` partition the 20,234 rows of
`vm_prefix_scenarios.py` (the closure-fuzz rows under their `vm_closure_fuzz.py` names). The SHA256C
(16) and DATASIZE (6) rows were already part of `vm-endstate`; `vmfam.py authored` runs their
authored checkers on those frozen effects.

Not converted: `pq-v16-parity` `bad-signature-ignore-classic` and `pq-falcon512-parity`
`invalid-ignore-classic` run with `VmState::set_chksig_always_succeed(true)`, which the `vm` context
does not carry. `native-cost`'s `--storage` and `--tariff` modes are not VM executions.

Fields the drivers report that the fixtures hold: all of them. Fields the fixtures hold that a driver
does not report: `test-pq-suite-parity` (committed, c4/c5, the stack beyond the result value),
`test-pq-v16-parity` and `test-pq-falcon512-parity` (steps, the stack beyond the result value),
`test-fee-native-cost` (steps, committed, c4/c5, the stack beyond the result value).

## RTOS families

Contexts from the RTOS tree at `42b39d44` (`vm/tests/data`), never its expected values. Families that
build their cases in Rust are taken from the JSON the test writes with its export variable set; that
JSON carries each code cell as the test built it.

| Family | Fixtures | Not converted | RTOS source |
|---|---:|---:|---|
| `rtos-opcode-gates` | 40,549 | 0 | `test_opcode_gates.rs`, export `RTOS_OPCODE_GATES_EXPORT` |
| `rtos-opcode-stack` | 4,032 | 0 | `test_opcode_stack.rs`, export `RTOS_OPCODE_STACK_EXPORT` |
| `rtos-continuation-save` | 14,228 | 0 | `test_continuation_save.rs`, export `RTOS_CONTINUATION_SAVE_EXPORT` |
| `rtos-continuation-chain` | 23,352 | 0 | `test_continuation_chains.rs`, export `RTOS_CONT_CHAIN_EXPORT` |
| `rtos-bchk` | 3,720 | 0 | `test_bchk_parity.rs`, export `RTOS_BCHK_EXPORT` |
| `rtos-library-budget` | 96 | 384 | `test_library_budget.rs`, export `RTOS_LIBRARY_BUDGET_EXPORT` |
| `rtos-poseidon2` | 3,087 | 0 | `test_poseidon2.rs`, export `RTOS_POSEIDON_EXPORT` |
| `rtos-sendmsg` | 12,280 | 8 | `test_sendmsg_parity.rs`, export `RTOS_SENDMSG_EXPORT` |
| `rtos-decode-matrix` | 10,144 | 0 | `test_decode_reference.rs`, `decode-matrix-cases.json` |
| `rtos-decode-vectors` | 364 | 0 | `test_decode_reference.rs`, `decode-vectors.json` |
| `rtos-pq-falcon512` | 872 | 4 | `test_pq_falcon512.rs`, `pq-falcon512.json` |
| `rtos-pq-suite` | 1,074 | 9 | `test_pq_suite.rs`, `pq-suite.json` |
| `rtos-pq-mldsa44` | 347 | 1 | `test_pq_mldsa44.rs`, `pq-mldsa44.json` |
| `rtos-lms-fee` | 512 | 4 | `test_lms_fee.rs`, `lms-fee.json` |
| `rtos-sha256c` | 454 | 0 | `test_sha256c.rs`, `sha256c.json` |
| `rtos-short-code` | 8,738 | 0 | `test_cont.rs` (`short_code_matches_reference`), `short-code.tsv` |

`opcode-activation` is not converted: its cases are a strict subset of `opcode-gates`.

Not converted, by the context field the `vm` harness lacks:

- `chksig_always_succeed` (`VmState::set_chksig_always_succeed(bool)`): the `ignore = true` cases of the
  four PQ families (18).
- `max_library_loads` (`VmState::set_max_library_loads(td::uint32)`): `library-budget` cases with a
  load limit (384 of 480; the 96 without a limit are converted).
- Integers outside 257 signed bits cannot be on a C++ VM stack: the `balance-wide` and `incoming-wide`
  contexts of `sendmsg` (8), whose value is 2^256.

Effects the RTOS tests compare that the `vm` effects do not hold: the final c0..c3 and the
continuation node table (`continuation-chain`, `decode-*`, through their digest), the error argument
and exit-item shape (`continuation-save`), and RTOS-only observations (raw errors, panics).

Set-up as each RTOS test has it: `Gas::test_with_limit(g)` is gas limit `g` under a maximum of 10^9;
`GasSetup::LimitIsMax` (the decode families) is limit = maximum = `g`; the tests that put an empty
tuple in c7 get `"c7": {"type": "tuple", "items": []}`, the others no c7; a test's empty library
dictionary is no collection.

`vmfam_rtos.py agree` compares the fills with the values the RTOS files recorded from older C++ builds
(exit, gas, and steps and committed where recorded): all equal except `rtos-opcode-gates` 2,
`rtos-pq-suite` 270 and `rtos-pq-mldsa44` 255 rows, all in the gas of ML-DSA-44 verification, which
the current C++ VM charges less than the build that filled those files (a valid suite-1 check: 57,127
recorded, 3,339 now; an opcode-gates ML-DSA-44 row: 50,156 recorded, 156 now).

## Reproducing

```sh
# tos families (deterministic ones regenerate in place; the PQ and native-cost ones take the
# scenario file their generator wrote)
build/crypto/pq/test-vm-opcode-table > cp0.tsv
python3 test/conformance/migrate/vmfam.py contexts vm-prefix ctx.jsonl --input cp0.tsv
python3 test/conformance/migrate/vmfam.py contexts pq-v16-parity ctx.jsonl --input scenarios.tsv
python3 test/conformance/runner/conformance.py create --reference build/test/conformance/conformance-ref-cli \
    --harness vm --family vm-prefix --source migrated:rescue-fee-gate/vm_prefix_scenarios.py \
    ctx.jsonl test/conformance/vectors/vm/fixtures/vm-prefix.jsonl
python3 test/conformance/migrate/vmfam.py check vm-prefix test/conformance/vectors/vm/fixtures/vm-prefix.jsonl \
    <(build/crypto/pq/test-vm-endstate prefix.tsv)

# RTOS families: an RTOS tree at 42b39d44 (git archive), the builder and the test exports
python3 test/conformance/migrate/vmfam_rtos.py build-asm <rtos-tree> <target-dir>
RTOS_OPCODE_GATES_EXPORT=gates.json cargo test --release -p rtos_vm --test test_opcode_gates
python3 test/conformance/migrate/vmfam_rtos.py contexts opcode-gates ctx.jsonl --data gates.json
python3 test/conformance/migrate/vmfam_rtos.py contexts decode-matrix ctx.jsonl \
    --data <rtos-tree>/vm/tests/data/decode-matrix-cases.json --asm <target-dir>/release/vmfam-asm
```

## Gates

- `conformance-vectors` runs every family against the reference.
- `conformance-vmfam-crosscheck` regenerates the deterministic tos families, requires their contexts
  to equal the frozen ones, runs `test-vm-endstate` and `test-pq-suite-parity` on the same scenarios
  and requires 0 differences.
- `conformance-vmfam-authored` runs the authored checkers on the frozen effects.
- `conformance-vmfam-tamper` adds 1 to one fixture's gas in a copy of `vm-prefix`, `pq-v16-parity` and
  `rtos-opcode-gates` and requires the runner to report exactly that mismatch.
