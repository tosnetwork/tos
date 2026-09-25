# X02 directed-run preflight (2026-09-25)

`scripts/x02_directed_run.py` drives one already-running, exact-tree Stage A
network using a SHA-pinned policy. It requires root for `tc`, records the
effective UID, argv, PID, source commit and policy SHA before touching `lo`,
and refuses pre-existing clsact or egress filters. It captures baseline,
six node4-cut rules, four additional node3-cut rules, two-of-four halt,
rule removal and four-node recovery. Each command and RPC/native snapshot
has a separate raw JSON file. A failed command, capture or verdict still
attempts removal of rules whose installation was attempted, then records the
resulting `tc` state. A non-empty filter or clsact after cleanup forces a
failed result and requires manual inspection; it is never a PASS.

Run Stage A with `--duration-seconds 900` or more and redirect stdout/stderr
to regular files, not a PTY. After its new readiness manifest appears, run
`x02_prepare_policy.py` as the ordinary user, retain its exact bytes and
SHA-256, then invoke the directed runner with `sudo -n` and that SHA. Do not
start another network or edit tracked source while this network is running.
The runner must finish within the Stage A deadline. The Stage A reward
allocation report and the runner's independent `result.json`/`verdict.json`
are separate outcomes: neither overrides the other. A failed Stage A report
does not turn a failed or missing fault verdict into PASS; a fault PASS does
not close outstanding allocation checks.

This is only the 100% directed peer-isolation first slice. Exact live `tc`
hit/drop, four process/socket identities, complete per-height raw
RPC/native joins and independent review remain to be collected. Partial
packet loss and the overall X02 unit remain OPEN.
