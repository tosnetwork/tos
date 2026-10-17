# Bootstrap readiness validation

Base revision: `d7ef85b4cccdc1dbad6b814ceb0b3714ef81dc08`.
The candidate source hashes, exact test names, exit codes, and bounded real
failure excerpts are in [validation.json](validation.json). This record covers
local behavior and regression sensitivity. **Live empty-database P2P bootstrap
and catch-up were not run.** That remains a publication gate in the
[operator guide](../../validator-operator-guide.md#11-refresh-the-global-configs-init-block).

## Results and execution boundaries

| Changed boundary | Test that exercises it | Observed result |
| --- | --- | --- |
| Snapshot selection, full IDs, refusal without output, remaining validity | `scripts/test_refresh_global_config_init_block.py` | 48 passed |
| Docker default, five deployment manifests, explicit overrides | `scripts/test_docker_validator_role.py` | 53 passed, 13 existing native-tool-dependent skips; all three retention regressions ran |
| Serving archive reads, proofs, split parts, budgets, actual deadline and lease lifetime | `test-bootstrap-state` | 9 passed |
| JSON-RPC/REST dispatch to manager, uncached readiness, admission and recovery | `test-json-rpc-transport` | 26 passed in the full target |
| C++ static analysis | Repository comparison gate | Exit 0; 0 new blocking, 0 new advisory; all 10 positive controls reported |

The final comparison exited 0 with 0 new blocking and 0 new advisory
findings. Both analyzers completed all 149 candidate and 146 clean-base
compilations, with zero failed analyses, and all ten positive controls reported
their marked findings. Earlier attempts refused with exit 2 for missing
development/generated headers; those prerequisites were resolved in both
checkouts before the complete passing comparison. They were not counted as
passing analyses.

The comparison uses the [repository's pinned gate](../../../AGENTS.md#static-analysis-gates-new-c-not-old-debt),
with a separate clean worktree at the base revision above. Both worktrees use
the same CMake options shown below. The final invocation is:

```bash
CCACHE_DIR=/tmp/tos-issue-232-ccache python3 -u scripts/static-analysis.py \
  --base d7ef85b4cccdc1dbad6b814ceb0b3714ef81dc08 \
  --build-dir build --base-build-dir ../tos-main-issue232/build \
  --llvm-bin /usr/lib/llvm-21/bin \
  --codechecker /tmp/tos-issue-232-tools/bin/CodeChecker \
  --jobs 4 --keep-temp
```

The explicit base pins the comparison to the recorded merge base even if
`origin/main` later moves. The initial complete comparison at commit
`1fee4c9b3660548d072b9c077382ab4cf0d5bdff` also passed; the invocation above
was repeated successfully after the formatting follow-up described below.

Here the CodeChecker path is the local virtual environment containing version
6.29.1. Install the normal native build prerequisites, including the microhttpd
and LZ4 development headers. If the provider contract header has not yet been
generated in a minimal build, build its normal Ninja target in **each** worktree
before dependency scanning; from each worktree's root:

```bash
CCACHE_DIR=/tmp/tos-issue-232-ccache \
  ninja -C build -j3 "$PWD/storage/storage-daemon/smartcont/provider-code.h"
```

## CI follow-up

The initial PR hygiene job reported four continuation-line indentations in
`download-state.cpp` and `download-state.hpp`. After aligning them with Clang 21,
the full changed-line formatter against the recorded base exited 0 with
`clang-format did not modify any files`. Ruff 0.15.2 check and format also passed
for all four changed Python files. Exact commands and the two updated source
hashes are recorded in `validation.json`.

The original complete CTest and mutation-control batches were executed before
the four-line indentation follow-up and were not repeated as a batch;
`git diff --ignore-all-space --exit-code` against the initial PR commit, restricted
to the two C++ files, exited 0.

The GNU ld CI build subsequently exposed unresolved manager references in the
transport test: `block_finality_broadcast_trace_id`, the `BlockHandleImpl`
constructor, and its vtable. The test now directly links `validator`,
`validator-common`, `full-node` and `tos_validator` after the RPC library, so the
common objects are included directly and `validator` precedes `full-node`.

The original generated link command, replayed with `-fuse-ld=bfd`, reproduced
the same unresolved symbols and exited 1. After the dependency correction, the
GNU ld link exited 0 and the resulting binary passed all 26 transport cases.
This replay used the exact CMake definition published in commit
`fc6898c64ca483302c4d6ac71707ccfa3bb5782f`.
The link replay reused already compiled candidate objects; it did not rebuild
the full native suite. These are separate linker and runtime results; the link
failure is not counted as an additional readiness-guard control.

This test-only dependency correction was configured while the static comparison
was in progress. All 1,011 compilation commands remained byte-identical. A
separate modification-time check found no generated C/C++ source/header file
rewritten after the preconfigure snapshot, so the comparison retained
the same C++ inputs. The exact link replay recipe and bounded results are in
`validation.json`. To repeat the target normally with GNU ld, configure the
build below with `-DTOS_USE_LLD=OFF`, build `test-json-rpc-transport`, and run its
exact CTest name with `--no-tests=error`.

## Repeat the green checks

Use the repository's build prerequisites and a configured Release build with
Clang 21, `TOS_ARCH=x86-64` and jemalloc enabled. From the repository root:

```bash
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-21 -DCMAKE_CXX_COMPILER=clang++-21 \
  -DTOS_ARCH=x86-64 -DTOS_USE_JEMALLOC=ON -DTOS_USE_LLD=ON
cmake --build build --parallel 4 --target test-bootstrap-state test-json-rpc-transport
ctest --test-dir build --output-on-failure --no-tests=error \
  -R '^(test-bootstrap-state|test-json-rpc-transport)$'
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_refresh_global_config_init_block.py -q
python3 scripts/test_docker_validator_role.py -v
```

`branch-chain-python.yml` builds both native targets and runs their exact CTest
names with `--no-tests=error`; the existing HTTP ingress step includes the
transport target. The Docker suite is an existing `source-guard` CTest.

## Failure receipts

The original refresh implementation failed three candidate tests: it selected
an unavailable latest key block, wrote output when no snapshot was served, and
accepted inadequate catch-up retention. Replacing it with the candidate made
all three pass. Freezing the clock before RPCs separately failed the slow-reply
validity test; restoring post-response sampling passed it.

The original Docker entrypoint and all five manifests supplied `86400`, producing
six assertion failures across three tests. The recorded fragments include
`'--archive-ttl 604800 ' not found` and the actual
`--archive-ttl 86400 --threads 8 --verbosity 3`, each six times. Restoring `604800`
passed all three tests. Explicit shorter/longer operator overrides passed in
both versions.

For those Python controls, make an isolated copy of the candidate test file and
its production inputs. Use `git show BASE:path` to replace only the production
script (refresh) or `docker/init.sh` plus `docker/tos-*.yaml` (Docker) with the
base revision above. Retain the unchanged `docker/validator-role.sh` and
`docker/control.template` in both Docker copies: the test setup needs them.
Run the named methods in `validation.json`, then restore the candidate production
inputs and repeat. Standard unittest selection is:

```bash
python3 scripts/test_refresh_global_config_init_block.py RefreshTest.TEST_NAME -v
python3 scripts/test_docker_validator_role.py EntrypointTest.TEST_NAME -v
```

The stale-clock substitution is recorded exactly in `validation.json`; apply
it only to the temporary refresh script. Expected outcomes are baseline exit
1 followed by candidate exit 0, with the named assertion reached.

All eight native controls compiled successfully, failed the intended runtime
check, then returned to green after restoration:

| Control | Runtime failure retained in the JSON receipt |
| --- | --- |
| Missing nonempty account part | `!missing_part.ready` |
| Truncated registered state file | `!run_readiness(archive).ready` |
| Missing archived shard proof | `!missing.ready` |
| Stalled read without actual timeout | `Deadlock detected` |
| Removed manifest budget | `manifest->reads (0 != 16384)` |
| Removed split-header budget | `too_large.reason (resource_limit != invalid_state)` |
| Removed two-query manager admission | `client.read_response(5000, status, body)` |
| Cached readiness after an archive change | `unavailable.find` |

Exact substitutions and expected failure matching are in the committed runner:

```bash
python3 scripts/check-bootstrap-state-controls.py \
  --build-dir build --output-dir CONTROL_OUTPUT --jobs 4
```

Add `--mutation NAME` to repeat one control. This runner temporarily changes
production sources and rebuilds them: use a disposable checkout with all other
builds and analysis stopped. It restores source bytes and green binaries in
`finally`. The three source hashes were checked against their originals after
the recorded run. A compilation failure is not counted as a successful red
control.

Cache-enabled transport startup also exposed a pre-existing constructor call
to `alarm_timestamp()` without actor context (`Check \`context_\` failed`).
Moving the existing timer setup into `start_up()` resolved that lifecycle
failure. It is recorded separately and is **not** a ninth readiness control.

## Evidence limits

The full native CTest run passed both targets, containing nine and 26 cases.
The Docker full-suite summary comes from its earlier observed execution; no
standalone log for that run was retained. This directory retains the actual
short assertions and result summaries, not entire stacks or repetitive logs.
Temporary log paths and their hashes are not claimed as durable, independent
artifacts; regenerate complete output with the commands above.

A ready snapshot and configured TTL do not prove every intermediate archive
still exists, recover pruned history, verify every snapshot byte, reserve future
availability, or establish remote connectivity. Before publishing a config,
complete the documented cold bootstrap and catch-up gate over the actual peer
path, including the transition while a newer snapshot is still unavailable.
