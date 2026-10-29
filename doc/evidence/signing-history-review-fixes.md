# Signing history recovery regression checks

These checks extend the review baseline `f927012095522eb091c24509ec9f7622cd83a754`.
The tests live with the code; raw build output is not needed to reproduce them.

## Supported-platform commands

```sh
cmake --build build --target test-signing-ledger test-startup-catchup-manager tos-pq-consensus-key test-fsync-dir-failure-shim
ctest --test-dir build --output-on-failure --no-tests=error -R '^(signing-ledger|test-startup-catchup-manager|consensus-key-tool)$'
PYTHONPATH=test/tostester/src python -m pytest -q test/tostester/tests/tostester/test_signing_log_soak.py test/tostester/tests/tostester/test_signing_fence_drills_exit.py test/tostester/tests/tostester/test_signing_unknown_history_drill_exit.py
```

The Branch PQ chain and Python workflow runs these three native CTests and the
complete Python suite. The manager tests cover a pending restart whose persisted
custody time is ahead of the new clock, and a stopped-node identity rebind with
the former identity's ledger still present. Both must eventually admit a session
above the new fence, after refusing the sessions within it.

## Local evidence and limits

- Python: 59 passed. The soak tests include both OFF and ON arms losing processes,
  fields or samples, changing PID/start time/role, ending early, and lacking the
  expected inventory. On the baseline implementation, the 19 added negative
  cases failed; with the fix, all 24 soak tests passed.
- Ledger suite: passed, including identity separation, restart without the original
  directory, return to the original identity with conflicting decisions refused,
  and refusal at the retained-directory capacity.
- C++ syntax checks: manager, manager tests and key tool passed.
- Ruff: passed. Basedpyright on the changed soak files: zero errors.

Local native checks used macOS, cached native dependencies, and a test-only adapter
mapping Linux `statx` inode/birth-time reads to Darwin `fstat`/`fstatat`, and
`fdatasync` to `fsync`. They establish functional behavior, not a Linux build or
Linux filesystem validation. The actual manager runtime and complete CLI suite
must pass the Linux CI gate above. The two-hour live-chain soak was not repeated;
previous resource averages do not establish the new process-continuity gate.

## Sensitivity controls

Each control below was applied separately to `signing-ledger.cpp`, rebuilt with
the unchanged test, and exited 1 at the named assertion. The restored source
exited 0 with `SIGNING_LEDGER_OK`.

| Removed behavior | Failing assertion |
| --- | --- |
| Max with persisted pending `header_.t0` in `history_start` | manager reads the persisted custody lower bound |
| Selection of the rebound identity directory on header mismatch | rebound identity must establish its own history |
| Retained identity directory limit check | one past the identity limit is refused for that reason |
| Startup selection of an existing identity directory | restart finds the identity ledger without the original |
| Bound-validator check before cached admission lookup | cached admission cannot cross the bound identity |

To repeat a control, disable only the corresponding guard/update, rebuild
`test-signing-ledger`, and require a nonzero test exit before restoring the source.
Never run a mutation against a live node.

## State and resource bounds

The new per-identity readiness flag uses fixed memory; the lower-bound query is
issued at custody change, with no per-block request queue. Replies to removed or
replaced custody records are ignored. The production engine holds one configured
validator identity for a process; changing it with `bind-node --replace` requires
a stopped node.

There are at most four retained identity directories beyond the original. On the
fifth, admission fails without creating another directory. They are never deleted
automatically; inactive identities keep no actors, in-memory session indexes or
open log files. Each directory retains the existing limits of 1,024 listed session
logs, 1 MiB per log, a 64 KiB header and four set-aside headers. Operator-created or
previously untrusted orphan files are not deleted by this change. An operator can
preserve and remove an obsolete directory while stopped; that identity then needs
unknown-history recovery if used again. Genesis initialization refuses retained
identity directories, including when the original directory is absent.
