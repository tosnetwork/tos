# Unknown-history drill on a local chain

This drill checks a claim in [signing-decision-log](../../signing-decision-log.md). A
validator that loses `consensus/` while a shard split is pending, and is restarted
within the same masterchain session, does not sign until the fence allows it:

- **With the own-decision log:** no own vote and no own candidate in any session at or
  below `cc(M) + 2` of its lineage. Signing resumes at `cc(M) + 3`.
- **Without the log (main):** it signs again at once, in the session it had already
  signed in.

The runner is `test/integration/signing_unknown_history_drill.py`.

## Setup

- A disposable local chain: global id 3, one DHT node and four PQ validators,
  basechain min_split 1.
- Catchain lifetime: 300 s for the masterchain, 60 s for shards.
- The chain runs in its own working directory on ports from 34000.
- Nothing else was used: no shared network, no `/data`, no service, no testnet host.
- The target is validator 3.

## How signing is observed

There are two independent observations.

1. **Signing boundary.** The target logs, once per session, the first candidate and
   the first vote of each kind (notarize, finalize, skip) that it signs. These lines
   come from `BlockProducer` and `Pool` right after `sign_consensus` returns. A
   signature is seen there whether or not it is ever published or ends up in a
   certificate.
2. **Certificates.** Every validator's certificates list the indices of the
   validators that signed. The target logs its own index for each session. A
   certificate counts only if it was obtained after the restarted target built its
   group for that session, because an earlier certificate can carry a vote the target
   cast before the stop that was still in flight.

## Runs

| | Log run | Control 1: main | Control 2: producer without admission checks |
|---|---|---|---|
| Source | `92cdaea2d` | `794bed0d5` (main), plus an INFO line logging the local index | `92cdaea2d`, plus [the producer patch](#retained-raw-output) |
| `validator-engine` sha256 | `aacd35e875578ceea9066db056b200736ba653886752b22607ccea69ef6e1733` (1) | `aa94b1cb10ec30617efea4d242f0271ffef70bf35f193b88c55919f6baeff830` | `765b520bed06a58cfbc251b58d9b4523e56f1f155f2ffd3704e98783932df17b` |
| Target | `--signing-decision-log`, genesis-ceremony ledger | no log | `--signing-decision-log`, genesis-ceremony ledger |
| Mode (`--mode`) | `log` | `control` | `producer-control` (run as `log`, before that mode existed; the setup is the same) |
| Observed for | `--observe 1320` | `--observe 420` | `--observe 600` |
| Split pending at the stop | `(0,4000…)` cc 1 tentative | `(0,4000…)` cc 2 tentative | `(0,4000…)` cc 1 tentative |
| Masterchain session at the stop / first one after restart | cc 0 / cc 0 | cc 0 / cc 0 | cc 0 / cc 0 |
| Target certificates in mc cc 0 before the stop | 50 | 42 | 31 |
| Fence (M, counters) | mc seqno 17: mc 1, `(0,4000…)` 2, `(0,c000…)` 2 | none | mc seqno 17: mc 0, `(0,4000…)` 1, `(0,c000…)` 1 |
| Sessions fenced after the restart | mc 0–3; `(0,4000…)` 1–4; `(0,c000…)` 1–4; `(0,8000…)` 0–3 | none | all at or below cc(M)+2 |
| Own signatures in fenced sessions | none (0 boundary lines, 0 certificates) | n/a | **a candidate in 12 fenced sessions** (mc 0–2; `(0,4000…)` 0–3; `(0,8000…)` 0; `(0,c000…)` 0–3), 0 certificates in any of them |
| Signing after the restart | first in mc 4 = cc(M)+3, `(0,4000…)` 5 = 2+3 and `(0,c000…)` 5 = 2+3; candidates and all three vote kinds | at once: 155 certificates in the old mc session cc 0 | — |
| Verdict | `passed: true` | `red: true` | `passed: false` (`no_signature_within_fence: false`) |
| Expectation of the mode / exit status | met / 0 | met (the control went red) / 0 | met (the control went red) / 0 |

(1) Built from the tree committed as `92cdaea2d`, before the commit. Only the embedded
build-version string differs.

Control 2 is the gap a certificate-only check leaves open. Its fenced candidates appear
in no certificate, so judging by certificates alone would have passed this run. The
signing-boundary lines catch it.

Summaries recomputed by the committed runner with `--analyze-only` in each run's mode, local paths removed:

| File | sha256 |
|---|---|
| [log-run.json](log-run.json) | `651f4bed868f57baba379b69454ff165f4f9d6b0f8645b94737338aeb6918095` |
| [control-run.json](control-run.json) | `c995f04dd875769323a4e0604183e38cfd47ed7a5f70313faf560f5ebfec9948` |
| [producer-control-run.json](producer-control-run.json) | `9733b2070e8741f16a29e42b56740c900c23254314c9350b1f9aa4a9e9fc3bf9` |

## Exit status: the drill as a gate

The runner exits 0 only when a run shows what its mode expects. It writes the summary
in every case, for diagnosis. A control's expectation is that it goes red, so a control
that stays green is a failure of the drill. The codes, also given in `--help`:

| Code | Meaning |
|---|---|
| 0 | Expectation met. `log`: the fence held and signing resumed at cc(M) + 3. `control`: main signed again in its old masterchain session. `producer-control`: the target signed a candidate in a fenced session. |
| 1 | The drill could not run or read its input (`DRILL_FAILED`). |
| 3 | `log`: signing within the fence, no resumption at cc(M) + 3, or no fence recorded. |
| 4 | A control mode did not show the violation it exists to show. |

`--analyze-only` uses the same codes. Replayed on the archived logs of the runs
above:

| Replay | Exit |
|---|---|
| run11 logs `--mode log` | 0 |
| run12 logs `--mode producer-control` | 0 |
| run9 logs `--mode control` | 0 |
| run12 logs `--mode log` (signing inside the fence) | 3 |
| run11 logs `--mode producer-control` (a control that stays green) | 4 |
| run11 summary with empty logs, `--mode log` | 3 |
| run9 summary with empty logs, `--mode control` | 4 |
| no summary | 1 |

`test/tostester/tests/tostester/test_signing_unknown_history_drill_exit.py` runs the
same cases without a chain, on synthetic logs, as part of the full pytest. Restoring the
old always-0 exit turns four of its eight tests red.

## Earlier runs (not evidence)

These runs predate the signing-boundary lines, so they count certificates only.

- **Run 10 (`e9d1ff9bb`).** The log run passed on certificates. Fence: mc 0, both
  shards 2. Signing resumed at mc 3 and at shard 5.
- **60 s masterchain lifetime.** The log run passed. The control on main showed
  nothing, because the old session ended before the restarted node caught up. That is
  why the masterchain lifetime is now 300 s.
- **Counting from the moment of the restart.** One analysis counted 3 old-session
  certificates obtained 0.12 s after the restart. They were votes cast before the stop
  and still in flight.
- **Port collisions.** Two attempts collided with another local network's ports. The
  default base port is now 34000.

## Retained raw output

The files below are on the build host under `/datax/drill-322/archive/`. They are kept
until #331 merges, plus 90 days.

| File | Size | sha256 |
|---|---|---|
| `run11-log-logs.tar.gz` (node logs, runner output, summary) | 28,070,651 | `35e8253468cbb5b505985acea5b5a7be47909274a6a70358373e24564e334ffb` |
| `run9-control-logs.tar.gz` | 9,929,310 | `e89883b8a2dbe19a9900b34466cb99a434c37dbe8cc859bc357692817a1ac9ec` |
| `run12-producer-control-logs.tar.gz` | 13,445,427 | `18c9f2894ba7b724f25c07922b14db0e34d7b2123634ee0d5d32b035b7ada404` |
| `main-794bed0d5-index-log.patch` (control 1's only change) | 774 | `04271ef72ebcf4ca5c7e8472308064292a64ebe371407da63856e94f55d7ad65` |
| `producer-admission-checks-removed.patch` (control 2's only change: both producer admission checks disabled) | 1,289 | `740e940072e4d2f7954e6e0e41055b7cf66f0f8f5a584e95f7345f2497938b40` |
| `run10-log-logs.tar.gz` (earlier run 10) | 27,891,082 | `bf7e5f936fbd2d252c066d1fff05c8f52b4ef6bfbd92f4241b40e7dde5602755` |

The full working directories, including the target's moved-aside `consensus.removed-*`,
are kept next to the archive.
