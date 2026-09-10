# Local UNO profile, regression oracle and configuration controls

This unit supplies an independent local network profile and repairs test
reachability. It does not claim M1 or account-batch execution acceptance.

## Local profile

`UNO_WORKCHAIN_PROFILE=1` in `scripts/setup-testnet.sh` selects version 16 and
requires a non-mainnet, non-Counter global ID. `NetworkConfig.uno_workchain`
uses the production genesis helper, descriptor a6 with flags c000, the exported
production engine key, and Param12/84 plus the issued instance ledger.
No Counter profile is reused and no UNO engine is registered. The validators
explicitly monitor the native basechain; they can carry the active workchain's
masterchain metadata without falsely declaring readiness to execute it.
`accept_msgs=0` remains the routing setting for this non-serving network.

The isolated three-validator/DHT run at ac2ba9266 reports all three validators
at masterchain sequence 14 and the restarted third validator at sequence 22.
Earlier unsuccessful experiments are retained with their actual limitations.
No existing /data network was cleaned or changed. Setup now checks generated
API modules and native/Python dependencies before any `--clean` deletion. Its
isolated deletion-sentinel mutation proves that ordering, not a production
application guard.

## Oracle and shared encoders

CTest passes the committed regression answer file to test-smartcont. Of four
individually regenerated live answers, only genesis changes (82bf2a... to
512112...). The other three match, and two answers whose tests were removed
are deleted. The isolated valid genesis mutation passes without an oracle,
fails the registered-argument CTest comparison with a different WA hash, and
passes after byte restoration. Explicit native rebuilds are recorded.

Workchain.fif now owns the a6 and a7 wire encoders, parameterized by routing
flags and engine selector. All five former bodies are library calls, including
cross-delivery's generated insertion. Five full descriptor BOCs match their
pinned predecessors; isolated route/key changes produce numeric identity 1221.
The generic, singleton Counter and dual-entry UNO profiles retain their distinct
14, 15 and 16 version requirements; the UNO setup switch explicitly selects 16.

## D58

The two ordinary activation test names now consume the existing scoped-resolver
probe and shared classifier, retaining Param84. They no longer ask a genesis
generator to construct an inadmissible state. Their scope is resolver rejection,
not live node execution or simulated transaction/export counters.

A separate test establishes whole-table and individual-entry continuity.
Deleting each check makes only its respective assertion (1231 or 1232) fail.
The transition predicate does not itself prohibit version downgrades; separate
presence rules require 15 for singleton ingress and 16 for custody-bearing
policies. The minimum-version activation check has its own isolated control.
Removing activation checks can expose a later rejection, so the control requires
the correct final typed identity through the shared helper, not merely an error.

## Merge condition

The old nine-row exception list must not be copied to a merge. Run readiness,
the two activation cases, disk integration, idle replay, self delivery, cross
delivery, native sender and engine configuration in the merged tree. Reconcile
every outcome against that tree's source and raw logs, including unexpected
changes from rejection to acceptance. A passing readiness test still asserts
the specified fail-closed readiness result; it does not certify account-batch
execution readiness. Activation's two redirected tests certify their stated
predicate scope, not the removed invalid-bootstrap path.

> **Superseding status (closed-gate M1):** Rust codec migration and controls are
> complete (`58d0b7fc7`, `ca350360d`); the Rust limitation in the historical
> paragraph below no longer describes current McStateExtra support. Runtime
> first-installation entry coverage and D54 are still separate from genesis.

Resource quotas remain provisional until M6. Runtime first-installation entry
coverage, the D54 activation-transition issue and the independent Rust state
codec limitations are not closed by these test-infrastructure changes.

## Recorded verification

The complete default build passed with `-j32`. The first ordinary run recorded
138 JUnit entries: 136 passed, two failed, zero skipped. The two failures were
individually explained from raw logs: missing TOL_STDLIB, and the routing test's
retired inline-encoding locator. After the environment correction and narrow
shared-call migration, both explicit follow-up tests passed with complete output
retained. The initial result is not rewritten as a green run. Each of the former
nine deferred tests passed in this tree; none remains deferred.

> **Superseding status:** The following is the retained initial result. Full
> topic/exact-path permission changes at `efe6b048a` and new-table calibration
> at `95c663aff` establish baseline zero, one injected retired diagnostic, and
> byte-identical restored output. Current scan is green.

The additional removed-domain scan is not green: 83 Uno-path diagnostics cover
14 files (31 exact lines already in a27ff2c77, 52 new or rewritten). Its allowlist
is unchanged. The exact-path comparison is recorded separately for coordinator
disposition; ordinary CTest results do not establish passage of that scanner.

Evidence: `doc/measurements/uno-local-profile`,
`uno-descriptor-and-oracle`, `uno-ingress-transition`,
`uno-descriptor-routing-followup`, and `uno-five-items-regression`.
