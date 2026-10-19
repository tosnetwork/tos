# Authenticated operator reads: final evidence

PR #152 implements the design in [elector-participant-list-read.md](../elector-participant-list-read.md).
The integration reviewed here is `6d247cae7`, plus the final CI and test changes.

## Accepted implementation

| Change | Commit |
| --- | --- |
| Shared VM context and independent parity oracle | `d79447d71` |
| Bounded execution and production-context budget measurements | `ca0c09099` |
| Three authenticated engine queries and completion exception containment | `511df73ce` |
| Checked Rust control APIs and adapters | `a0dcf6681`, `cf1fcfe55` |
| One elector snapshot per operator decision | `0ca2a0a51` |
| Operator proposal reads through control | `3ced5a423` |
| Real-engine process integration, including an old engine | `6c60222ff` |
| Accepted integration | `cc5d2d85e`, `6d247cae7` |

The final tests add distinct nonzero returned credits (11 and 22) through the real
ADNL client and production elections provider. Both reach recovery's funding check;
the fixture has zero wallet balance and broadcasts nothing. An active pool's
controller identity matches its frozen record. Separate late frozen/returned amount
overflows preserve the populated snapshot, history, accepted stake and recovery amount.

## Bounds and measured budgets

Two worker lanes, eight queued reservations, 16 distinct returned-stake wallets,
256 participants, 16 histories, 256 frozen entries per history (4,096 total),
4,096 proposals, and an 8 MiB boxed reply. Responses are complete or refused.
Request admission precedes state lookup. VM execution, flattening and destruction
run off the engine actor; no VM-private state or actions are applied.

Production-context measurements and the reproducible gate are in
[budget-results.txt](../../test/validator/fixtures/control-getter/budget-results.txt)
and `control-getter-budget`.

| Worst measured elector shape | Gas | Budget | Headroom | Unused budget |
| --- | ---: | ---: | ---: | ---: |
| Deepest 256-member book, maximum stake | 1,114,595 | 1,500,000 | 34.5780% | 25.6937% |
| 16 deep-path histories, 4,096 frozen entries | 19,528 | 50,000 | 156.0426% | 60.9440% |
| Deepest credit lookup | 26,804 | 40,000 | 49.2315% | 32.9900% |
| Combined read with 16 wallets | 1,552,487 | 2,190,000 | 41.0640% | 29.1102% |

Headroom is `(budget - gas) / gas`; its floor is 30% for the bounded elector
cases. Contiguous and hashed history IDs cost 15,953 and 17,878 gas.
Proposals instead have a 10M operational ceiling, with no headroom guarantee:
4,096 hashed unvoted proposals cost 9,431,419; 512 deep-path proposals with
21 voters cost 8,547,745; a single lookup costs at most 38,512. Count, gas and
reply limits refuse explicitly; incremental proposal reads remain future work.

## Key-guard sensitivity

Each listed control was run in an isolated worktree/build, failed its intended
assertion, and passed after restoration. Ordinary tests cover other checks.
The retained native runners predate the lighter final process; no new runner or
control index was introduced for the final work.

| Guard | Break and test that catches it |
| --- | --- |
| Authorization before work | Remove engine permission check: `real_engine_authorization_and_unknown_flags` refuses the resulting flags error in place of not-authorized. Native service control also checks zero lookups. |
| Unknown flags | Remove both engine/service flag checks: the same process test refuses the resulting successful answer. |
| Per-run gas | Lower returned-stake budget to 20,000: native budget test fails `returned-deepest`. |
| Aggregate gas | Charge zero instead of VM consumption: native VM test fails `vm-aggregate-only-refused`. |
| Wallet/list/history/count limits | Raise each limit by one or admit a duplicate wallet: query service/boundary tests fail the corresponding refusal; 4,097 proposals are not published. |
| Returned-wallet binding | Substitute the returned address or getter argument: query test fails `returned-order` / `returned-wallet-amount-binding`. Rust DTO controls also reject missing, reordered and substituted entries. |
| One query per decision | Add a second shared control read or runner provider read: CLI/runner counters fail, including confirmation polls. A tick-specific test asserts one provider invocation. |
| No public elector fallback | Restore the four legacy getter calls in the provider or CLI helper: method-specific public counters fail. Their positive control successfully calls all four getters and the legacy connection probe. |
| No public proposal fallback | Restore CLI list/detail reads or the service fallback after the named upgrade error: public list/detail counters fail. |

Completion exceptions are additionally tested in a subprocess: removing the
catch terminates the child and fails `completion-exception-survived`; restoration
lets the next job finish. No mutated source remains in the integration.

## Reproduction and gate scope

Use a separate Ninja/clang-21 Release build with the CI flags and
`TOS_WERROR_BUILD=On`. Build all native targets and the standalone PQ key tool
against the build's static OpenSSL. Rust gates use the locked workspace and an
independent target directory. Set `TOS_ROOT` to this checkout, `PQ_KEY_TOOL` to
the built tool and `TOS_PROOF_VERIFY` to the built verifier for the sandbox tests.

```sh
cmake --build build --parallel 8
cmake --build build --parallel 8 --target all-tests
ctest --test-dir build --parallel 8 --output-on-failure --no-tests=error
cargo test --manifest-path tosctl/src/Cargo.toml --workspace --no-run --locked
cargo test --manifest-path tosctl/src/Cargo.toml --locked \
  -p contracts -p commands -p elections -p service -p control-client
```

The explicit engine gate uses `TOS_SOURCE`, `TOS_ENGINE_BUILD`, and `TOS_OLD_ENGINE`:

```sh
cargo test --manifest-path tosctl/src/Cargo.toml --locked -p control-client \
  --test engine_operator_reads -- --ignored --nocapture
```

All three process cases passed locally. The old binary is the accepted build of
`6da705c8a`, copied read-only for this rerun (SHA-256
`587a56d6a50f73da4592969cbab41e82b8a0742bd15794895093b07e047d1e44`),
not a new build claimed by this final step. Each API preserves the downcastable
`UnsupportedControlQuery` through caller context. CI builds the current engine
and runs the two `real_engine_` cases with `--ignored`, requiring exactly two
passes; rebuilding the old revision is intentionally a local gate.

Strict Clippy retains the reviewed production-library baselines: contracts 109,
commands 117, service 44 (test targets contain additional pre-existing diagnostics).
The gate is zero diagnostics intersecting PR-added/changed lines, with no new
suppression. Cargo fmt, changed-line clang-format, changed-Python Ruff and whitespace
checks are part of the final gate.

Final results: the full strict native build and `all-tests` build passed. The
parallel CTest run completed all 360 registrations: 349 passed, three failed,
and eight were disabled. `test-dht` and `test-twostep-wiring` then passed when
rerun serially. `consensus-key-tool` passed after building its excluded fsync
shim through `all-tests`; the first run's missing shim was a setup failure.
The changed native selector separately passed 22/22. Thus every enabled test
passed either initially or on its recorded recheck; a clean first parallel run
is not claimed.

The locked Rust workspace test compilation passed; touched-crate suites passed
1,579 tests with 16 default ignores. Three of those ignored process tests were
explicitly run separately (3/3); the other 13 ignores predate this work.
Commands passed 207/207 after the test-helper lint cleanup;
elections passed 59/59, including both added credit/late-overflow cases. The exact
CI new-engine command passed 2/2. Whole-PR changed-line Clippy filtering passed
for all five touched crates, as did formatting, Ruff and whitespace checks.

## Seven-node live gate

The controller performed the approved rolling `systemctl` deployment of the
engine built from `511a3de34`; the chain advanced through every restart. All seven
local nodes answered both control reads at a common block, equal to the public
getters at that block: closed election and history IDs at masterchain block
252372; open election at block 253120 with four identical participant IDs, stakes
and order. This is controller-reported live evidence, separate from the final
isolated process tests. The final step makes no additional service changes.

Public explorers keep their existing getter limits. Complaint commands are outside
the migrated routing table. Pool/wallet balance reads at other blocks can still
over-count funds returned between reads, as recorded in design section 5.4.
