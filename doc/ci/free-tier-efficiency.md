# CI efficiency within the shared concurrency limit

The reference is main commit `c253e9e9c7cd9c1aaa6f9a6ca6ee223621529efe`.
The measured rescue run `38853477571` completed in 68m02s. Its longest worker
ran for 44m10s after a 22m06s runner queue; 37 jobs from the same PR shared
capacity with earlier builds. Increasing a matrix limit cannot increase the
organization's available runner slots.

## Ready-event reuse

The Lint, authentication and quantum-readiness workflows still run on opened,
reopened, synchronize and ready_for_review events. Normal PR updates always
execute their full jobs, including draft PRs. Pushes to main and manual runs
also execute the full jobs.

Only ready_for_review can reuse evidence. Each job compares the PR number,
head SHA, base SHA, actual checked-out Git tree, workflow blob and job/architecture
identity with an artifact from an already successful run of the same workflow.
The artifact must state that tests actually executed in that run. A reused job
does not publish another executed receipt, so evidence cannot form a reuse chain.
The job summary links the original successful run. Attempt-specific artifact names
avoid collisions on retries; earlier executed receipts remain usable after a
successful partial retry of the same source/run.

A changed base, tree, workflow, architecture or job forces execution. Missing,
expired, oversized, malformed or inaccessible evidence also forces execution.
The first run after deploying this feature has no prior receipt and cannot be
skipped. Receipts are written only after successful tests and a clean tracked
source tree. Both automatic architectures and existing required check names are
retained. Artifacts are retained for 14 days.

The lookup uses repository-scoped Actions read permission. It never extracts
artifact paths to disk, bounds archive and receipt sizes, and drops API credentials
before following the artifact-storage redirect. No write permission is added.

## Main native object reuse

Both full native workflows use the existing native-cache action with a dedicated
`main-shared` profile, bounded to 1 GiB per archive. CPU/instruction-set, compiler
contents, OS and runner-image identities remain part of cache isolation. Cache
configuration is created outside the restored object directory. The build script
honors the action's cache directory and maximum size instead of resetting them.
Compiler flags, production-build guards and all build targets remain unchanged.

This caches compiler objects, not test outcomes or mutable signing state. A cold
cache still performs a complete build. A PR branch's newly written cache is not
evidence that main already has a warm cache. The repository-wide cache budget
and competing Rust caches remain constraints; this change does not increase the
GitHub quota.

## Closed-PR cache maintenance

A separate daily maintenance workflow reclaims at most 20 cache entries whose
`refs/pull/<number>/merge` or `/head` scope belongs to an independently confirmed
closed PR. Open PRs, main, branch and tag caches are preserved. The PR state is
checked again immediately before deletion. API or inventory errors do not grant
permission to delete. The cache API is separate from test-result artifacts.

The only Actions write permission is confined to this maintenance workflow. It
has no PR trigger, requires the default branch, and checks out default-branch
code with persisted credentials disabled. Manual dispatch defaults to a dry run;
scheduled runs apply the bounded cleanup. No production runtime data is involved.

## Bounded CTest parallelism

Only `test-db`, `test-tdutils`, `test-bigint`, `test-vm` and `test-cells` execute
in a two-worker phase. Their native source has no source-code mutations or
network listeners. DB files (`test_celldb`, `compact_array_db`, `serialization*`)
and tdutils log/temp files have distinct names. VM/cell regression caches are
already per executable. The shared answer file uses the existing stable sidecar
lock, merge and atomic replacement in RegressionTester; the existing
regression-fixture-concurrency check is retained. All other tests, including source mutations and network
fixtures, execute afterward with one worker. Unknown future tests default to
serial execution. Existing CTest arguments, working directories, timeouts and
properties are retained.

The runner loads the full CTest registry, rejects missing audited tests and
unaudited dependencies on the parallel units, and partitions the registry without
omissions or duplicates. It runs both phases even if one fails and fails the job
on any failed phase. It verifies that the registry did not change during the run.
CTest's existing RUN_SERIAL/resource properties continue to apply.

This is deliberately a small parallel group; no blanket `ctest -j` is applied to
source mutation or network tests. Full Linux x86/ARM validation is still required.

## Validation and remaining acceptance

`test/ci/efficiency-contract.json` pins 41 original workflow command bodies and
skip conditions. Its only test-runner replacements retain the complete registry.
The assembly script is compared with the baseline after normalizing the two
intentional cache-setting changes. These guards and their negative controls run
in the required source-guards job.

```sh
python3 scripts/test_ci_snapshot.py
python3 scripts/test_ci_ctest.py
python3 scripts/test_ci_efficiency.py
python3 scripts/test_clean_closed_pr_caches.py
python3 .github/actions/native-cache/test_prepare.py
python3 .github/actions/native-cache/test_smoke.py
python3 scripts/check-rescue-context-ci.py
python3 scripts/test_rescue_context_ci.py
```

The CTest runner tests use real temporary CTest projects to prove two-worker
overlap, complete execution, serial isolation and failure propagation. Snapshot
negative tests cover changed identities, unsuccessful runs, API failures, archive
bounds and credential stripping. Removing the corresponding guards must make
these tests fail at their intended assertions.

A one-hour outcome is an acceptance target, not an established result. Measure
cold/warm full native runs on both architectures and a repeated Ready event on
the exact same validated snapshot. Retain the complete Linux/ARM results and
both rescue parity gates. Multiple simultaneous PRs can still exceed the shared
capacity; this change provides no scheduler priority or reserved runner slots.
