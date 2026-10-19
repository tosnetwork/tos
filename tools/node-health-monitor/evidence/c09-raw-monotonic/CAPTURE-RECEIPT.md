# C09 bounded local raw capture and soak audit receipt

Date: 2026-09-30 UTC. This is a read-only local observation of the existing
profile. No business service, M, collector, Edge or QueryService was restarted;
no model API, AURA grant or node RPC was invoked.

## Source and running identity

- Starbridge source: `nhm/c09-raw-monotonic@28877d02875ceaaa848d04f6d73bc655dc46ee14` before this receipt.
  `perf/raw_monotonic.py` SHA-256:
  `d36a96a6484192a6ff02c2e447c6b1b203b59e7e03eb200384011d32f69ed89d`.
- Shared timer correction: `afdd738eadc62cd6d3960aa86c475816a96d8555`.
  `nhm-c09-q-soak-stop.timer` was active, next UTC elapse
  `2026-10-03 01:10:00`; `nhm-c09-soak.timer` was active. The old stop timer
  was absent. This corrects the calendar window only.
- Running QueryService PID `3847778`, `/proc/3847778/exe` SHA-256
  `e37f9c4353bb80f5ae8acd3a941d7eeb21b5f116a448448adb79588fb94cf8ee`.
  Deployment receipt binds it to source `31fc2f615ec3325d0e6bfe69f37f692068786bc0`;
  its `observability.rs` blob SHA-256 is
  `ee8097797892c1329ae0c4de258d103d52ef87a27c3eb1d16f39871cce847919`.
  `GET /healthz` returns a static service availability response and does not
  read a business node or M evidence. It does not prove QueryService data
  freshness or validator health.
- Existing soak sampler SHA-256
  `7faffd24459d6bb6b095110df121f6e6b36f68ef22573de7a3050a208c38ca72`;
  private Q probe script SHA-256
  `996a2db57aecf0c4653e1eb0f23afccbc52452c0935b4d7c0ff6f8de75279665`.

## Exact commands and raw files

```sh
systemctl --user list-timers --all --no-pager --plain | rg 'nhm-c09-soak'
systemctl --user show nhm-c09-q-soak-stop.timer -p ActiveState -p NextElapseUSecRealtime -p Result
sha256sum /proc/3847778/exe tools/node-health-monitor/perf/raw_monotonic.py
python3 tools/node-health-monitor/perf/raw_monotonic.py \
  http://127.0.0.1:19491/healthz \
  tools/node-health-monitor/evidence/c09-raw-monotonic/query-healthz-8.jsonl \
  --count 8 --timeout 2 --deadline-seconds 30
```

The same-process `linux:CLOCK_MONOTONIC_RAW` capture retained 8/8 successful
HTTP 200 first-byte durations; zero dropped/invalid/stopped-early. API-reported
clock resolution is 1 ns; this is not a measured accuracy bound. Raw durations
in ns: `4986456, 1753145, 886413, 723327, 688652, 505780, 504321,
505454`. Min/median/max: `504321/705989/4986456` ns. The first request is
included and no p99 estimate is produced from eight samples.

| File | SHA-256 |
|---|---|
| `query-healthz-8.jsonl` | `5689e2eb5c7de6a8fce4e05b48602a70594598ac119fcc61e5bcdc7d79705dd8` |
| `query-healthz-8.jsonl.manifest.json` | `6738e136ffccb2c6570defd5c9da80a78613c5e8cc07e7bcaaf779df333edda6` |
| `soak-audit-prefix.jsonl` | `a54231cac85567546d699362b56cf921941d2460fb6709945c19dc48677486c7` |

The fixed soak prefix was copied from complete newline-terminated rows only:
294,818 bytes, 176 rows, from `2026-09-29 21:56:23Z` through
`2026-09-30 01:00:24Z`. The last 23 rows contain the Q probe, starting
`2026-09-30 00:38:14Z`. In that prefix: zero sampler errors, nonfresh-node
rows, nonactive-unit rows, gaps over 120 seconds, Q conflicts or failed Q
probes; maximum inter-row gap 72.361 seconds, maximum Q lag 21 M sequences.
This short prefix is not a continuity verdict. The live source JSONL continues
to grow after the copied prefix.

## Performance population and open gates

The live six node processes all had `--health-core-metrics` and no measurement
JSONL argument. This is one C-like local operating state, not a frozen A–F
comparison. The captured population is only `external_request_rtt` for the
static QueryService endpoint; the manifest marks V, edge, M, O and A resource
ledger entries `not_run`. Internal proposal/vote/storage stages have no
same-process paired native raw hooks in this run. No node CPU regression,
internal-stage p99, 30-minute alternating round, high/max approved load,
72-hour completion, rotation/restore/rollback, physical independent failure
domain or production-doctor pass follows from these files.

The narrow next comparison is: freeze identical source/binary/config and raw
native stage hooks, then obtain A/B using approved same-binary toggles or an
explicit old-commit bridge in an isolated development node profile. Compare
normal/high/maximum-approved workloads in at least three alternating 30-minute
rounds after warmup; add C fixed collection, D diagnostics, E approved
external AI and F development colocated AI only as separately budgeted
profiles. Preserve the currently running business services. Record completed
work, deadlines, oldest queue age, typed progress, actor occupancy and all
V/edge/M/O/A CPU/RSS/IO/network beside raw stage samples. Until that evidence
exists, the R4 1% CPU and 3% key-p99 gates remain `not_run`/`inconclusive`.
