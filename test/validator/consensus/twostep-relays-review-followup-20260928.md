> **Superseded by owner ruling R7.** This is historical evidence for the withdrawn refusal policy. See [twostep-relays-r7-validation-20260928.md](twostep-relays-r7-validation-20260928.md) for current behavior and new tests.

# PR #120: independent review follow-up — 2026-09-28

**Status: test corrections committed; revised native build, runtime tests and mutation checks are pending. Not a merge approval.**

Reviewed head: `e362b03307d4f6016a25568b1e0ba428876e3c56`, against base `2483ea590b736f018a0fac8daf190510e0cef506`. The original [implementation report](twostep-relays-review.md) and [JSON record](twostep-relays-validation.json) describe the implementer's run against `e4bf266bf6b1b7b9a7bf80c0e727afb94c9bd531`; the originally reported 124/124 CTests and 14 mutation classes / 17 executions must not be relabelled as runs of this revised source.

## Verdict and scope

The reviewed sender restriction, permanent-peer intersection, current-total-set selector, synchronous factory checks, both bridge initializers, Bus/overlay wiring, manager eligibility gates and empty-observer handling match the intended bounded port. No additional definite production-code defect was established in those changes by this source review. This is not proof that the implementation has no defects.

The changes in this follow-up are confined to three test sources and this review record. Production code, canonical session identities, TL, signatures, two-step receive/rebroadcast, QUIC, collator and consensus-DB retirement are unchanged. The review does not merge or deploy the branch.

## Findings and corrections

### R1 — P1 acceptance gap: total-set switch did not isolate key-block binding

Original `TotalSetSwitchRecreatesActiveAndObservers` prebuilt the two-member `next.set(2)` committee, then activated `next.set(2, 1)`. These committees have different session-hash members. Therefore merely observing a different tentative/active ID does not establish that the key-block input prevents reuse: the member change can produce that difference independently.

Corrected fixture:

- Prebuild `next.set(2, 1)` while the outgoing current total set is still installed.
- Activate that **same committee object**, with the same catchain sequence number, configuration and membership; change the last-key-block input through the real manager update.
- Observe that the prepared Bus really carries the outgoing current relay snapshot.
- Derive the expected identities with the production function. The true-mode IDs differ when only key-block seqno changes from 0 to 2; the false-mode IDs do not.
- Match the actual manager's tentative and active/observer IDs against those expected values, then retain the incoming-relay and observer-delivery assertions.

This fixes an insufficient test oracle, not an observed production wrong-epoch relay incident.

### R2 — P2: the same-total-set control used a committee outside that total set

Original `SameEpochTentativeCanBeReused` left `current` unchanged but promoted the disjoint `next` committee. It exercised map reuse under a synthetic inconsistent state rather than an ordinary within-total-set catchain transition.

The corrected control has no next total set, prepares the next catchain committee from `current`, and explicitly checks committee membership in that total set. It promotes exactly that prepared committee without a key block. One local validator reuses its tentative Bus; the current-set observer gets the new session. Both retain the same current relay snapshot. A new Bus count of exactly one distinguishes observer recreation from unnecessary tentative-validator reconstruction.

### R3 — P2: asynchronous fixture readiness could be premature or unbounded

`Fixture::advance` previously stopped when accumulated historical overlay and Bus counts matched, even if the latest update's newly registered groups had not yet reached their Bus observation point. It also fell through silently after 100 polling rounds. Three `while (!done)` waits had no local bound.

The corrected fixture obtains the real manager's active/observer/tentative session inventory, waits until those sessions have observed Buses and the corresponding overlay constructions are present, and fails explicitly on a bounded pump budget. Promise waits use the same bounded helper. This remains a threaded RootDb fixture, not a claim of deterministic wall-clock or socket behavior. Exhausting the wait is a harness failure, never a successfully killed mutation.

### R4 — P2 test coverage: sorting was not distinguished from already-sorted input

The original selector test supplied ascending ADNL addresses and asserted ascending output. Removing the production sort could therefore preserve its result.

The fixture now uses transport-address order `62, 60, 61` for the current set while keeping validator IDs and key IDs distinct. It asserts that the input is not already the expected sorted vector, and still requires `60, 61, 62` from the real selector. Existing duplicate-address normalization and null/empty cases remain.

### R5 — P2 test coverage: nominal FEC target and transmitted source-symbol count

The old `expect_fec_symbols(k)` helper treated one value as both the nominal `floor((n-1)/2)` target and `ceil(D/part_size)`. They coincide in the existing 8,000-byte fixtures but need not coincide generally.

The helper now checks `k_target` and `source_symbols` separately against actual captured first-hop frames. New `FecRoundingUsesTransmittedPartSize` covers:

```text
permanent members = 63, remote relays = 62
payload D         = 513
k_target          = floor(61/2) = 30
transmitted part  = ceil(513/30) = 18
source symbols K  = ceil(513/18) = 29
```

Only the source is online. This is a generic-overlay emitted-parameter test, not a 63-validator consensus launch or a remote decoding/liveness claim. The two offline-member fixtures retain their original remote-delivery assertions with explicit `(9,9)` and `(2,2)` target/source-symbol pairs.

## Evidence boundaries

The review read the PR diff, production lifecycle/identity paths, the current work order and the submitted test evidence through the GitHub connector. Local `git clone` in the review container failed because that container could not resolve `github.com`; consequently the reviewer did **not** compile or execute the revised native C++ tests. Connector repository access and writes are independent of that container limitation.

The original Ubuntu native workflow `36400698800` was still in progress when inspected and was pinned to the old `e362b033...` head. Even a later successful result for that run would not validate these changed tests. Check the exact tested SHA before recording acceptance.

The existing candidate fixture signs and serializes an **empty PQ consensus candidate** and observes overlay reception/deserialization while delegating to the production handler. It does not prove non-empty block execution, consensus finalization, candidate-resolver recovery or a deployed QUIC transport. Those boundaries remain unchanged.

The recovery fixtures use a later valid key-block configuration. This review does not broaden that evidence into a guarantee of reopening an already retired identical signing session; the durable destroyed-session fence has deliberately not been weakened.

## Required validation for the revised head

There are now **20 focused native cases**: nine transport, two selector, nine wiring/lifecycle, still registered through the same three CTests. This is a source inventory, not a passing-test count.

From an existing correctly configured QUIC-enabled build, using the project's resource-admitted job counts:

```sh
cmake --build build --target test-overlay-twostep-relays test-current-validator-adnl-ids test-twostep-wiring
ctest --test-dir build --output-on-failure -R '^(test-overlay-twostep-relays|test-current-validator-adnl-ids|test-twostep-wiring)$'
git diff --check
```

Confirm that all three named CTests actually ran; zero selected tests is not acceptance. Then rerun the original 124-test affected selection and its build targets using the original JSON's commands, and record a **new** result against the revised head rather than changing the identity of the old record.

In addition to rerunning the original mutation checks, add these targeted, compiling mutations and restore each afterward:

| Mutation | Required detection |
|---|---|
| In `ValidatorManagerImpl::update_shards`, temporarily use a constant/stale `key_seqno` instead of the updated last key block, leaving `new_catchain_ids=true` | Corrected total-set-switch case detects reuse/ID mismatch and cannot pass because of a committee-member change |
| Remove `std::sort` from `block::current_validator_adnl_ids`, retaining offset-zero selection and deduplication | Unsorted transport-address fixture fails its sorted-result assertion |

Both must fail on the intended runtime assertion, not compilation failure or harness timeout. Restore mutations and rerun the clean tests. Also run the corrected same-epoch reuse control and the new FEC rounding case on the clean revision.

**Merge gate remains open:** revised native compilation, corrected runtime cases, mutation evidence and the applicable CI checks on the final branch head are still required.
