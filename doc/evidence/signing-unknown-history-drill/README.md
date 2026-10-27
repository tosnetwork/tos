# Unknown-history drill on a local chain

The drill tests what [signing-decision-log](../../signing-decision-log.md) claims. A
validator loses `consensus/` while a shard split is pending, and is restarted within
the same masterchain session. With the own-decision log, it does not sign in any session
at or below `cc(M) + 2` of its lineage, and it signs again from `cc(M) + 3`. Without
the log (main), it signs again at once in the session it signed in before.

Runner: `test/integration/signing_unknown_history_drill.py`.

**Setup.** The chain is a disposable local chain:

- global id 3, a DHT node and four PQ validators;
- basechain min_split 1;
- masterchain catchain lifetime 300 s, shard catchain lifetime 60 s;
- its own working directory, on ports from 34000.

No shared network, `/data`, service or testnet host was used. The target is
validator 3.

**Judging.** A signature counts only if it appears in a certificate obtained after
the restarted target built its group for that session. Two checks:

1. Certificates on all four validators carry the signing validators' indices.
2. The target logs its own index for each session.

## Runs

| | log run | control run (red) |
|---|---|---|
| Source | `e9d1ff9bb` (this branch) | `794bed0d5` (main) plus one INFO line that logs the local index ([patch](#retained-raw-output)) |
| `validator-engine` sha256 | `929e92be6be3528f5f2caadb86347658caf15346397634bbee536c1b519495e7` | `aa94b1cb10ec30617efea4d242f0271ffef70bf35f193b88c55919f6baeff830` |
| Target options | `--signing-decision-log`, plus a genesis-ceremony ledger (`tos-pq-consensus-key` sha256 `b68d5c8c…7dcb`) | none |
| Command | `--mode log --mc-lifetime 300 --shard-lifetime 60 --observe 1320` | `--mode control --mc-lifetime 300 --shard-lifetime 60 --observe 420` |
| Split pending at the stop | `(0,4000000000000000)` cc 1 tentative | `(0,4000000000000000)` cc 2 tentative |
| Masterchain session at the stop / first after the restart | cc 0 / cc 0 (same session) | cc 0 / cc 0 (same session) |
| Target signatures in mc cc 0 before the stop | 35 certificates | 42 certificates |
| Fence block M | `(-1,8000000000000000,16)`; counters: mc 0, `(0,4000…)` 2, `(0,c000…)` 2 | none |
| Sessions fenced after the restart | mc 0–2; `(0,4000…)` 1–4; `(0,c000…)` 1–4; `(0,8000…)` 0, 1, 3 | none |
| Target signatures after the restart in a fenced session | 0 | n/a |
| First session signed after the restart | mc 3 = cc(M)+3; `(0,4000…)` 5 = 2+3; `(0,c000…)` 5 = 2+3 | mc 0 (155 certificates in the old session); `(0,4000…)` 1; `(0,c000…)` 1 |
| Verdict | `passed: true` | `red: true` |

Summaries, recomputed with `--analyze-only` by the committed runner:

| File | sha256 |
|---|---|
| [log-run.json](log-run.json) | `d22ea0e499cbeb8678641fae794e39e8a5c8e0395f08cbf4d06fe323f6cc98a4` |
| [control-run.json](control-run.json) | `d0bc0d106e0dccea090b76ff9ef592143cb262f4503c1173551aa26f848d66ea` |

Local paths have been removed from both files.

## Earlier runs

The runs below are not counted as evidence. They show how the drill was set up.

- With a 60 s masterchain lifetime the log run also passed (fence counters 2/2/2,
  signing resumed at cc 5 on every lineage). The control run on main showed nothing,
  because the old masterchain session ended before the restarted node caught up. That
  is why the masterchain lifetime is now 300 s.
- An earlier run counted certificates from the moment of the restart. It found 3
  certificates of the old session with the target's signature, all obtained 0.12 s
  after the restart. They were votes from before the stop that were still in flight,
  so signatures are now counted only from when the restarted group was built.
- Two attempts collided with ports another local network uses. They were stopped,
  and the runner now defaults to base port 34000.

## Retained raw output

The raw output is kept on the build host under `/datax/drill-322/archive/` until #331
merges, plus 90 days.

| File | Size | sha256 |
|---|---|---|
| `run10-log-logs.tar.gz` (node logs, runner output, summary) | 27,891,082 | `bf7e5f936fbd2d252c066d1fff05c8f52b4ef6bfbd92f4241b40e7dde5602755` |
| `run9-control-logs.tar.gz` | 9,929,310 | `e89883b8a2dbe19a9900b34466cb99a434c37dbe8cc859bc357692817a1ac9ec` |
| `main-794bed0d5-index-log.patch` (the control build's only change) | 774 | `04271ef72ebcf4ca5c7e8472308064292a64ebe371407da63856e94f55d7ad65` |

The full working directories, including the target's moved-aside
`consensus.removed-*`, are kept beside the archive as `run10-log/` and `run9-control/`.
