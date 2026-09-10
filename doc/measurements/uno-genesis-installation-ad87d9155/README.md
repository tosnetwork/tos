# Genesis and routing evidence

Implementation: `ad87d9155f7ed38798d8b0a647cf209f289609b5`.
Consumer followup: `573df2f3c` (full hash in report.json).
No milestone acceptance is claimed. See report.json for commands, limits and
individual full-regression failure explanations.

The full ordinary run has 137 JUnit entries: 133 passed, four failed, none
skipped. A separate five-test consumer followup passed after fixing two of the
four failures. These are separate runs, not a rewritten 135/137 full run.
The two old node activation tests remain blocked before activation at 7409.
The scoped probes retain Param84 but do not supply node transaction/export
observations. They cannot discharge that live boundary obligation.

| Original nine Counter cases | Current full-run observation |
| --- | --- |
| account-binding-readiness | Passed its existing typed readiness-stop contract; no account-batch execution claim |
| disk-integration | Passed |
| idle-replay | Passed |
| self-delivery | Passed |
| cross-delivery | Passed |
| native-sender | Passed |
| engine-config | Passed |
| activation-missing_capability | Failed generating its Param84-less genesis: 7409 |
| activation-old_version | Failed generating its Param84-less genesis: 7409 |

The Python codec suite and generated-tag checks also passed. Full manager
synchronization/cold-join and large-snapshot experiments were not enabled by
this ordinary configuration; no result is inferred for unregistered tests.

| Control | Isolated observation |
| --- | --- |
| Remove create-state issuance | Generated state exists, but required seq=1 is absent: 936 |
| Remove destination accept_msgs guard | Serving two-block case stays green; unserved action result fails 957 |
| Remove ledger delta comparator | Correct genesis accepted; missing-entry and changed-descriptor candidates each fail rejection expectation 931 |
| Approve unlisted mainnet operators | Operator predicate control 984 |
| Remove operator generator guard | Generator boundary control 985 |
| Approve provisional mainnet resources | Both branches complete interpretation; mainnet boundary fails 990 |
| Remove empty Counter business predicate | Valid shell decoded first; business rejection fails 1127 |
| Replace requested old version with version 16 | Probe's disabled-success stop 323 fires; this deliberate input mutation is not an unexpected baseline activation |

There are nine restored-source records because the delta comparator was rerun
to exercise the second negative after the first driver's intentional early
stop. This is one guard with two inputs, not two independent protections.
`restore-audit.json` reconstructs every substitution from its recorded commit.
Mutation copies and their binaries were isolated from repository sources and
normal build outputs. Explicit restored target commands are in each report.

Failed fixture construction, dependency/setup mistakes and the initial missing
Tol library build are retained and excluded from behavioral evidence. Live node
database directories are omitted; exported candidates, generated zerostates,
fixture source, final typed sidecars and full logs are retained. One verbose VM
log is losslessly compressed, with its original hash recorded separately.

Persistent routing observations cover two successive source blocks and this
sender's send modes. They do not prove every message mode or indefinite queue
liveness. Genesis shared-routine coverage does not cover the runtime collator
issuance entry. D54, operator Rust decoding and M6 quota acceptance remain
explicit blockers in the implementation document.
