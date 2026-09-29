# C05 external-witness development candidate — supervisor review requested

This candidate continues the accepted C04 branch at `88d5d95ad`; it is
**development-only**, not deployment or production-source acceptance. No
business node, key, chain endpoint, P2P permission or main merge was touched.
The source gap is explicit: current edge/native outputs lack an approved
external finalized-block anchor; C04 consensus slot is not a block sequence,
and on-demand `getNodeConsensusStatus` is not a cache-only witness. All
witness traffic/tests here use isolated synthetic fixed HTTPS caches and
private test mTLS identities. No deterministic proof verifier exists, and
`observer_disagreement` does not receive a live witness fact.

## Contract and behavior coverage

| R4/C05 decision | Actual source-bound control | Limit |
|---|---|---|
| Full network/genesis/raw scope/anchor context; no highest-height or quorum laundering | `health-core/tests/witness_contract.rs`, `health-services/tests/witness_cache.rs` and strict witness plan/source schemas | Reported anchors only; verified finality remains false |
| Same slot/different session, unfinalized candidate disagreement, missing vote | Strict source decode plus five separate row dimensions in those tests; source comparison cannot emit a node fault from a remote report alone | No production vote visibility |
| Bounded plan, one poll per unique approved endpoint, four real child-task permits, 15-second no-catch-up, late/timeout isolation | `tests/witness_poll.rs`, `tests/witness_cache.rs` | Third-party remote cancellation is not claimed; O restart restoration unsupported |
| O's own heartbeat/notice outage distinct from target V fault | `tests/witness_poll.rs`, `tests/watchdog.rs`; runtime evidence in `RUNTIME-SUPERVISION-RECEIPT.md` | Test receiver is not a production human-delivery receipt |
| Historical archive distinct from current age/ordering | `tests/witness_archive.rs`, `tests/ingress.rs`; actual O→mTLS→collector→mTLS→M path and wrong token/clock/hash controls | Historical ACK is local archive commit only; no rule input |
| 1 MiB volatile M current budget and read/body lifetime | `CURRENT-BUDGET-CHECKPOINT.md`; exact 32-row decoded track/view size, exact cap arithmetic, response-body and queued-timeout permit controls | Not SQLite/whole-process heap or production cost gate |
| Changed-property sensitivity | `current-age-mutant.patch` and baseline/compiled-red/restored logs in the budget checkpoint | One current-age mutant here; earlier C05 child-lifetime and O-lane mutants remain in their original receipts |

The final source/contract/test/log inventory for this candidate is
`C05-HASHES.sha256` (39 independently recomputable entries; run
`sha256sum -c tools/node-health-monitor/evidence/c05-external-witness/C05-HASHES.sha256`
from the repository root). Its SHA-256 is
`fc1ff1df61a1d131aa776ffeda1294695b3b41815ddf597f393babb8188c0fe5`.
Earlier slice logs and their failure lineage are indexed by `CHECKPOINT.md`,
`RUNTIME-SUPERVISION-RECEIPT.md`, `CURRENT-M-SLICE-RECEIPT.md` and
`TRANSIT-CHECKPOINT-RECEIPT.md`. `CURRENT-BUDGET-CHECKPOINT.md` binds the
restored final-source tests plus the one compiled current-age mutation.

The locked `scripts/run-contract-tests.sh` raw log naturally exits 0 with
24 closed schemas, actual HTTP success outputs, genuine production doctor
refusal of 11 unverified gates, and 179 active workspace tests. Five targeted
entrypoint executions are additional and not counted again; one native C04
producer-pair test stays ignored without an indexed external C++ pair input.
The latest manifest-only edit was independently rechecked by
`raw/current-manifest-contracts.log` (exit 0). Restored fmt/Clippy and
targeted 9 lib + 7 ingress + 9 archive runs are indexed in the budget
checkpoint. No fresh broad rerun is inferred from the mutation/manifest edit.

## Open gates

- Production finalized-block/cache source, deterministic proof verification,
  validated cost/performance and restart restoration of O quarantine are
  unsupported. Source manifest remains `complete_manifest=false`.
- C05 current output is a bounded development context report with
  `production_usable=false`; a missing or stale source yields
  unknown/unavailable, not a successful zero or node fault.
- Real witness rule input, production receiver/failure-domain evidence,
  deployment, C06+ work and main merge were not attempted.

Request scoped C05 source/evidence review at the exact candidate HEAD. A
reviewer should judge this dev-only slice and the explicit open gates, not
interpret isolated synthetic qualifications as production finality.
