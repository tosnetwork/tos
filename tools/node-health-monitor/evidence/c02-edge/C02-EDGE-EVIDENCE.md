# C02 edge candidate evidence

Scope: basic-only C02 edge access from accepted C01
`e460faa8403ae583bba21855abeb0e2ed81090ed`. The semantic implementation
predecessor is `b736cca8c1b73166d311cf214be2e3432b19046e`; the final artifact successor
adds only frozen manifests and indexed evidence.

## Implemented boundary

- `health-edge` remains the sole native collection owner. Remote routes are
  cache-only; 1,000 HTTP attempts (most are intentionally 429 under the fixed
  rate budget) retain one source call. Separately, 1,000 direct `r4_snapshot`
  cache reads retain one typed source read, and a mismatch gets one typed
  read with no retry.
- Actual heartbeat (4 KiB), capabilities (32 KiB), snapshot (256 KiB), and
  metrics (2 MiB) paths are bounded. The contract entrypoint captures actual
  handler bytes for the first three and validates their closed schemas.
- Process, native, and optional cgroup sources must share a process epoch in
  both the producer and M parser. Copied old-epoch wire is refused.
- Cgroup-v2 reads only configured fixed files through at most 16 descendant
  levels. The mount root is unconstrained; the tightest finite ancestor memory
  limit and exact CPU ratio win. Current usage above a newly lowered limit is
  retained as pressure, not discarded. Unlimited, zero, missing and symlinked
  descendant controls remain unavailable/error.
- Total TLS connection lifetimes stay at eight. Seven classified ordinary
  connections hold their permits until `serve_connection` completes, leaving
  the eighth slot for either approved heartbeat identity. Both ingress and
  edge request buckets reserve their fourth token. Eight authenticated sockets
  that finish TLS but send no headers temporarily exhaust all slots; the HTTP
  header timeout then releases them and the next heartbeat succeeds.
- Preclassification does not claim unconditional heartbeat availability. TLS
  handshake and HTTP header phases have separate three-second bounds and may
  occur sequentially.
- `validator_stats`/getStats and readiness remain disabled or unsupported. No
  request-triggered RPC, arbitrary passthrough, C03 behavior, business node,
  key, deployment, consensus, journal, or durability change is included.

## Restored results

- `CARGO_BUILD_JOBS=2 ./scripts/run-contract-tests.sh`: exit 0. It validates
  20 closed schemas, actual emitted edge wires, six existing tool successes,
  the 11-gate production refusal, and 111 workspace tests.
- Workspace C02 counts include: cgroup 4, lifecycle 1, HTTP 15, ingress 5,
  native cache 6, native typed 7, and native-contract 5.
- The actual `NativeSampler::run` slow-source witness takes 17.52 seconds:
  one synthetic source completes after 16.5 seconds and no immediate catch-up
  call occurs. Its 20-second client timeout is test-only; production remains
  three seconds. The pure schedule boundary test remains alongside it.
- `cargo fmt --all -- --check` and locked workspace Clippy with warnings denied:
  exit 0.
- Six C02 changed-property mutants compile, run, and fail their intended
  assertions: cgroup root, pressure truth, mixed epoch, router heartbeat token,
  classified connection lifetime, and missed-tick skip. Compile failures do
  not count. Each baseline and mutant has a separate raw log.
- The connection-lifetime baseline proves the intended discriminator: seven
  real authenticated TLS clients do not read 2 MiB responses; an eighth
  ordinary request is 429 before upstream count changes, an approved heartbeat
  succeeds, and after one connection is released an ordinary request returns
  2 MiB and advances the upstream count from seven to eight. The early-release
  mutant reaches the wrong assertion and exits 101.
- Supervisor independent restored execution of that ingress test exited 0.
  Its binary SHA-256 is
  `774720bb86cbb42f9ca932b569f2c533c9c7e688af5198d9eabd5c04e5061df0`;
  the external raw log is
  `/home/tomi/nhm-supervision/c02-independent-ingress.log`, SHA-256
  `236a1b5015e026efac3cd95133f696ca73e99a89db47065feb9cf67fac5f11b7`.
  The supervisor also independently ran the restored contract checker at exit
  0. These are independent review receipts, not production acceptance.
- An isolated real `health-edge` test process can be killed without signalling
  or restarting its configured synthetic source process.
- Actual `/metrics` and `/v1/edge/snapshot` handlers return 503 for cold,
  stale, same-generation-conflicted, and new post-restart cache state; a
  duplicate same-generation observation does not renew the original age.

## Historical failures retained as lineage

During reconciliation, the pre-C02 HTTP test expected a legacy process-only
snapshot success and failed after required-native enforcement. Initial epoch
tests reused a native fixture with a different real process epoch and failed
until fixtures were truthfully bound. The first seven-connection test used a
16.5-second upstream delay but was masked by the production three-second
client timeout; a later unread-response attempt showed that the OS could buffer
2 MiB until the receive buffer was explicitly bounded. None of these runs is
counted as passing evidence. The final test uses an actual 1 KiB requested TCP
receive buffer, a rate-budget control, and the connection-owned permit.

## Remaining gates

This candidate does not certify production fixtures, effective deployment
quotas, host placement, credentials, failure-domain isolation, contiguous-work
budgets, Prometheus/Alertmanager, performance, soak, or any C03+ behavior.
Process and cgroup fixtures are explicitly isolated synthetic controls sharing
the synthetic native fixture epoch; they are not production host receipts.
