# R7: relay preparation cannot stop consensus groups

## Authority and identity

- PR #120 branch: `fix/twostep-current-validator-relays-20260928`.
- Amendment parent: `8edb093e8cb7e4ae6aeb2a505ffa8fc4c3b156f3`.
- Integrated production baseline: `2483ea590b736f018a0fac8daf190510e0cef506` (`origin/main`).
- Work-order checkout: memo `1e055bfb1c53f106ae20687e6b5d850217f3bb9e`, including R7 revision `5faea6dd`.
- Work-order file SHA-256: `cc6d2692f5c79d8e70ff649c2cd4351af4abdfa919fd771f23b26960602cf212`.
- Tested code commit: efb88c6b9fe406ef7461ff158eab6357082deb16.
- The changes identified by `b997745e` and `ef1cddd2` retain the permanent-peer intersection. R7 changes only the relay-snapshot failure consequence to the pre-port legacy policy.

## Work order §12 mapping

| Item | Implemented amendment |
| --- | --- |
| 1 | Manager returns an optional snapshot. Missing state, false prerequisite and missing/empty current set log warnings and return `std::nullopt`. Snapshot preparation occurs immediately before each factory, after unrelated refusal checks. All three `update_shards` loops and tentative cleanup are restored. A byte comparison confirms the entire `update_shards` region matches `origin/main` except the retained observer empty-actor check. |
| 2 | Both required factory parameters and `BridgeCreationParams` use the optional type. The shared normalizer logs an error and converts a present empty or non-member snapshot to legacy; it never refuses an actor. The unconditional Bridge startup CHECK is removed. |
| 3 | Bus defaults to legacy. Both overlay sites set the option only for a present, non-empty snapshot. Membership, source authorization, receive handling and session identity are unchanged. |
| 4 | `scripts/check-pq-unsafe-rotation.py` is byte-identical to `origin/main`; the guard and its seven mutation controls pass. |
| 5 | Refusal oracles are replaced by manager fallback/recovery, running flag flip, direct factory normalization and a real committee-ceiling observer refusal. A separate false-before-prebuild total-set switch observes broad first hops on the reused group. Four real networking fixtures explicitly assign a current-only set. |
| 6 | All five prior evidence files are visibly marked superseded, with links to this report. Fresh commands, admissions, runtime assertions and hashes are in the accompanying JSON. |

No TL, signature, consensus-ID, configuration-contract, DHT, QUIC, collator, receive-handler or candidate-resolver changes were added. No merge or deployment is performed by this review package.

## New oracles and traces

The wiring test now has thirteen cases, in addition to nine overlay cases and two selector cases (24 native cases in three CTests).

- False prerequisite, null current set and zero-member current set each use a fresh fixture. Actual active/observer entries must be started and non-empty; tentative entries must be non-empty and not started. The actual Bus and options must select legacy. Returning to valid data creates current-only snapshots again.
- Running true → false → true changes canonical session identities through the unchanged production algorithm. Active and observer groups are replaced by running legacy groups, rather than removed without replacement. An older true-prerequisite tentative group may remain, as required by the work order's unchanged cleanup predicate.
- The new prerequisite-negative switch sets false before preparing the identical next committee. Production legacy identities match across the key-block change; the manager actually reuses that tentative actor. Its snapshot is absent and its first hops remain all permanent members. Ignoring the prerequisite produces outgoing-only first hops and is caught by the runtime trace.
- Direct factory cases use protocol 2, distinct sessions for every call, and broad previous/current/next membership. The outside identity belongs to none of those sets. Both actors are non-empty; their captured snapshots and options are legacy. Only the active factory originates a broadcast.
- Every broadcast clears first-hop and delivery records, uses a distinct candidate, and filters by the actual overlay ID. The trace records case, session, overlay, first-hop destinations and candidate deliveries. Previous tests' historical records cannot satisfy a later case.
- Sparse B2 fixtures prove group lifecycle and first-hop selection, not decoding availability. An early calibration incorrectly expected two observer deliveries in that sparse fallback topology and failed. That expectation was removed from B2, where it is not required. Real positive observer delivery remains mandatory and passing in the populated protocol-2 and protocol-1 C1/C3 fixtures, and in the original transport cases.

## Tests and mutation results

- Clean build: **45 affected targets**, exit 0 (Clang Release, `-j8`).
- Focused coverage: **24 native cases** executed in the three registered CTests.
- Affected regressions: **124/124 CTests**, no failure or skip.
- Source guards: **39/39 CTests**, including the restored unsafe-rotation guard and all **7** of its mutation controls.
- Combined runs: **159 distinct CTests / 163 executions** (four source guards overlap).
- Native mutation matrix: **21 compiling variants / 23 executions**, all intended reds and restored. This covers all **19 required §9 variants**, plus the retained stale-key-block and missing-sort controls.
- Empty-normalization mutation: CHECK `!bus.all_current_validators->empty()` at private-overlay.cpp:100; abort stack confirmed, observed process exit 1.
- Observer-empty-check mutation: CHECK `!empty()` at ActorOwn.h:81; abort stack confirmed, observed process exit 1.

Exact build/test commands and complete selected test lists are recorded in [the JSON](twostep-relays-r7-validation.json). The main commands are:

```sh
cmake --build build --target <45 targets listed in JSON> -j8
ctest -V --test-dir build --output-on-failure --no-tests=error --output-junit <regressions.xml> -R <exact 124-test regex in JSON>
ctest -V --test-dir build --output-on-failure --no-tests=error --output-junit <source-guards.xml> -L source-guard
python3 build/twostep-r7-validation-20260928/run_mutations.py
```

Each native mutation record contains its exact build command and `<binary> --filter <case>` invocation, original/mutated source digests, observed process exit, intended assertion, log digest and byte restoration. The two abort records additionally retain the CHECK and libc abort frames.

All §9 variants compile before execution, fail for their intended runtime reason, and are restored. Additional stale-key-block and missing-sort controls from the independent review are retained. The two specified abort variants retain their CHECK messages in the JSON; they are deliberate reds, not clean-test failures.

The final clean build and regression runs occur after restoration. Three focused translation units also pass their configured Clang commands with `-Werror -fsyntax-only`; this is not a full repository strict-build claim.

## Scope and reproducibility

Local configuration: Ubuntu 22.04.5, Clang 21.1.8, CMake Release, Ninja, `USE_QUIC=ON`. Builds use `-j8`. Fresh whole-host CPU/memory measurements precede each mutation build and final stage, including existing services. Forecast additional CPU/memory is recorded and remains within the owner's two-thirds limit.

Raw logs and runners are retained under `build/twostep-r7-validation-20260928/`. The accompanying JSON records commands, outcomes, admissions, mutation assertions, restoration and evidence digests. All five historical records remain history only; none is promoted as proof of the new behavior.

The simulator does not prove real QUIC latency, multi-host availability, governance execution or production throughput. Remote CI is a separate gate on the final pushed head; local passing evidence does not label a pending CI run successful.

Public command paths use `${REPO_ROOT}` for the repository directory. The unchanged host invocations remain in the hash-listed local command records. The CI changed-line formatter command also passes (no changes).
