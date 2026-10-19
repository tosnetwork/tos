# Local C09 acceptance preparation

The owner authorized real local-node operation on 2026-09-29. The baseline
is four PQ validators, two non-validator observers and the local DHT. This
host is a single physical failure domain, irrespective of service isolation.
Existing unrelated data is preserved. No main merge is implied.

`scripts/local-acceptance-sample.py` records complete public masterchain IDs
and the prepared Genesis identity, fixed process/cgroup CPU, anonymous RSS,
swap, I/O and memory-event counters. It never reads keys, seed, environment,
block databases or scans database directories. RPC request times are recorded
with a monotonic clock and explicitly are **not** consensus-stage p99. Its
fixed RPC schedule is a declared acceptance instrument, not an extra owner
of the native metric source. Native source ownership still belongs to edge.

Each output directory is exclusive; samples are capped at 128 MiB. Failed
proc/cgroup/RPC reads are retained as errors and cause a nonzero terminal.
Missing I/O controller accounting must be enabled and recorded before every
profile. A successful short startup calibration is not a performance gate,
finality proof, or 72-hour soak. All groups retain the same instrument.

Example (operator-owned paths):

```sh
sudo python3 tools/node-health-monitor/scripts/local-acceptance-sample.py \
  --out "$ACCEPTANCE_ROOT/calibration" --seconds 60 --interval 15
python3 tools/node-health-monitor/scripts/test_local_acceptance_sample.py
```

## Before performance and soak

- Freeze the integrated C06/C08 binary, source/config/dependency manifests,
  approved model profile, generated development Genesis and role inventory.
- Freeze effective cgroup limits, log level, transfer/privacy workload and
  cadence, warmup, normal/high-load/maximum connection profiles, sampling
  population and raw consensus-stage measurement method.
- Build the A–F toggles or an explicit old/new bridge. Obtain actual raw
  stage durations with identical instrumentation in every group; RPC RTT or
  coarse histogram interpolation cannot prove the 3% p99 requirement.
- Run at least three alternating 30-minute rounds after warmup per approved
  profile. Apply the original 1% CPU/3% p99 conditions and report uncertainty,
  throughput, deadlines, oldest queues, progress and actor occupancy.
- Exercise active-incident backup/restore, retention/quota, upgrade/rollback,
  certificate/receiver rotation, separate-process failure and alert recovery.
- Start a bounded 72-hour soak only after the integrated candidate is frozen.
  Do not count a baseline calibration, interrupted run, or pre-integration
  uptime toward that gate. Retain a natural terminal and per-gate evidence.

Real provider validation and physical independent receiver evidence require
an approved endpoint. Synthetic provider controls cannot substitute for them.
Doctor must preserve fail/not_run/inconclusive rather than upgrade scoped
development receipts into production acceptance.
