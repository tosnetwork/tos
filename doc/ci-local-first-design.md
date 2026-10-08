# Local-first CI: redesign for main and the Quantum candidate

Date: 2026-10-08. Status: **design proposal with an implemented phase-zero inventory**.

## 1. Decision and delivery boundary

Make the execution contract portable before changing the service that schedules it.
Local Ubuntu and GitHub should call the same reviewed scripts, with the same declared
inputs, immutable builder image and build profile. Reuse compatible compilations;
never reuse a previous test verdict as evidence for a new candidate.

This change delivers this design, a pinned workflow-directory inventory, an offline
inventory/drift CLI, and tests in the existing `CI cache validation / cache-contract`
job. It does **not** deliver a full local runner, publish a new builder image, replace
required checks, deploy a self-hosted runner, or change a validator host. The later
`ci/run`, catalog, image lock and shared suite entrypoints below are planned interfaces,
not commands that this PR has already implemented.

The optimization branch starts from main, independently of PR #138. No wallet changes
are copied into it. Main-only extraction can be reviewed independently; conversion of
Quantum suites must use the actual post-merge source after #138 lands, with a refreshed
inventory. Neither this design nor a green inventory test approves the wallet release.

### Pinned source basis

| Input | Exact identity |
| --- | --- |
| Main at inspection, B | `b121f3a45366d8d8516ffa61923312c05accb64d` |
| PR #138 head, H | `99ec7e18299c78a944ca83f4e041dbf374a2dcf8` |
| PR branch | `feat/v5r2-rescue` |
| GitHub test-merge commit observed, M | `ece27ad3e5962c01d5b8276aee97c7dab75070b2` |
| B workflow directory | `7c7d836f60d780d70d9eeaa1072e953b6ea9f495` |
| H workflow directory | `63202c3db63bde088cc7203166719e931c5813db` |

These are observation snapshots, not moving aliases. The inventory compares **B and
H**, not M. The complete M tree and its jobs have not been executed in this review.
The PR API reported #138 open, not merged, and not draft; historical text in its body
still describes an incomplete draft candidate. Release status must be established
from current source and acceptance evidence, not that stale label.

Sources: [main][main], [PR head][head], [PR #138][pr138], and the two directory object
IDs reconstructed and checked by [the committed baseline](ci-local-first-baseline.json).

## 2. What changed since the earlier plan

The directory listing is **50 workflow files on B and 54 on H**: four added, four
modified, none removed. This is a count of files, not runnable jobs or matrix cells.
The earlier memo's 49 files / 77 job definitions and historical wall times are not
current measurements. No complete current job-count or run-latency claim is made here.

| Workflow | Change in #138 | Boundary that must survive optimization |
| --- | --- | --- |
| `admission-work.yml` | Added | Real native admission, manager/pool/CLI limits and compiled deletion controls on x86 and ARM |
| `quantum-mobile-native.yml` | Added | Separate native crypto project, durable fee-state tests and executable C ABI on Linux x86/ARM and macOS |
| `quantum-readiness.yml` | Added | Actual genesis/configuration transitions, retirement and fee-schedule sensitivity on x86 and ARM |
| `rescue-context.yml` | Added | Native/Rust transaction parity, generated configuration, signing/custody/fee-tree and recovery controls on x86 and ARM |
| `auth-extension-validation.yml` | Modified | V5R1 baseline retained; Quantum identity, AUTH, state, fee bounds, config transitions and SDK checks added |
| `branch-chain-python.yml` | Modified | Proof-query HTTP behavior and compiled controls; disposable Quantum configuration and payment execution linkage |
| `contract-sandboxes.yml` | Modified | Nine additional proof/state/fee/policy/receipt/payment-control steps, without dropping existing sandbox suites |
| `wallet-falcon.yml` | Modified | Namespace input coverage and x86 live fixture changes from version 16 to **19**, including the final evidence assertion |

The four added files alone contain nine expanded platform cells. This does not count
additional steps in existing jobs or establish full release-acceptance coverage.
Every file and its exact blob identity is retained in the baseline. Inspect the full
[H workflow directory][head-workflows] before extracting any execution step.

### Existing infrastructure is useful, but not yet an equivalence contract

`Dockerfile.builder` already provides Ubuntu 22.04 and 24.04 builders. The branch-chain
job already uses the Ubuntu 24.04 image. The problems are not an absence of Docker or
an absence of all caches:

- Consumers use a mutable `:ubuntu-24.04` tag; the builder workflow refreshes that tag
  monthly. Independently pulling it at different times does not fix the same image.
- The Dockerfile downloads x86_64 uv binaries; the 22.04 stage also downloads x86_64
  ripgrep. It is not already a validated multi-architecture builder.
- It exports `CC=clang-21` and `CXX=clang++-21`. Moving a host-default-compiler workflow
  into that image could silently replace GCC with Clang. That is a profile change,
  not a mechanically equivalent migration.
- Main now authenticates LLVM package installation with a repository-pinned key and
  checks standalone tool archive digests. Do not restore unchecked install scripts.
- Several suites already use the native-cache action and Rust caches. Falcon still
  has no native-cache restore in its build path. Identify actual misses and repeated
  work before asserting that every workflow rebuilds everything from scratch.

These findings come from [the builder][builder], [its publication workflow][builder-workflow],
[the strict workflow][strict], [the native-cache preparer][native-cache] and
[the Falcon workflow][falcon]. The earlier [Forgejo proposal][forgejo-plan] remains
useful background, but its rollout is deferred; this design does not authorize it.

## 3. Define precisely what "the same CI" means

There are three different claims:

1. **Execution-contract parity:** same source snapshot, commands, selected tests,
   assertions, feature flags, tool versions and declared inputs. This is the target
   for a migrated suite and must have a comparison receipt.
2. **Runtime-profile parity:** additionally the same OCI platform image and controlled
   resources/network layout. Docker shares a host kernel and exposes host CPU behavior;
   it cannot make arbitrary Ubuntu hosts and hosted VMs identical.
3. **Platform qualification:** native architecture/OS, real GitHub event/ref semantics,
   authorization, artifacts/attestations and publication. These remain explicit remote
   or platform-specific obligations where local machinery does not implement them.

A matching image digest fixes the image contents, not the kernel, scheduling, clock,
network failures or a newly downloaded dependency. An independently rebuilt Dockerfile
using moving apt repositories is not necessarily that same image. A deterministic
unit test can agree while a timing-sensitive integration test differs. Do not promise
bit-identical binaries without a separate reproducible-build investigation.

Ubuntu 22.04 can host an Ubuntu 24.04 userspace container on a compatible machine; it
cannot thereby run native macOS jobs. ARM emulation is useful preflight, not replacement
for native ARM timing, ABI and implementation checks. Keep the macOS cell of mobile
crypto, and the other Windows/macOS/release workflows, on their supported platforms.

`act` can help debug supported workflow syntax and steps, but is not the acceptance
engine: its documented unsupported/ignored features include important scheduling,
permission and timeout behavior. The shared execution contract should not depend on
an Actions emulator interpreting every provider feature. See [act limitations][act]
and [GitHub job containers][job-containers].

## 4. Architecture: one execution contract, two adapters

```text
Reviewed source B/H/M + explicit event/matrix context
                    |
           Versioned execution catalog
             /                     \
     Local CLI adapter       GitHub workflow adapter
             \                     /
         Same script + profile + immutable image
                    |
          Compatible baseline build producers
             /         |          \
       Read-only    Independent    Isolated mutation
       consumers    live fixtures  source/build copies
             \         |          /
          Per-suite results and coverage reconciliation
```

Proposed files, to be implemented in later bounded changes:

```text
ci/catalog.json              # suite, profile, dependencies, platform, required evidence
ci/images.lock.json          # reviewed OCI references/digests and per-platform identity
ci/run                       # local planning and execution adapter
scripts/ci/<suite>.sh         # shared commands, with explicit arguments and environment
scripts/ci/check_coverage.py  # reconcile expected and observed assertions/controls
```

Do not turn `catalog.json` into a second hand-maintained copy of all YAML commands.
Extract commands into scripts first; adapters reference those scripts. The catalog
specifies stable suite identities and prerequisites, not shell snippets duplicated
between local and hosted execution. Reject unknown suites and unsupported conditions.

An entry must declare at least: source mode, profile, platforms, build targets,
working directory, environment, fixtures, dependencies, mutation/exclusive resources,
timeout, expected test/control evidence and a result schema. Preserve shell semantics:
container job `run` defaults to `sh`; suites using arrays or pipelines need explicit
Bash with appropriate failure propagation. A successful final `tee` must not conceal
a failed command earlier in the pipeline.

### Builder release and consumption

Prepare images in a separately reviewed toolchain pipeline. Record the platform,
OCI digest, OS package list, compiler/linker hashes, CMake/Ninja/ccache versions,
repository-pinned Rust version, Python 3.14 where needed, uv and required JS tooling.
Keep repository tool-pinning checks in the image build and consuming verification.
Use existing verified acquisition logic rather than adding a new unchecked installer.

An image is promoted only after its verification fixtures pass. The promotion PR
updates the image lock; ordinary code PRs consume that immutable digest. Do not insert
an invented digest or silently fall back to `latest`. Image changes are separate
qualification events, even when only a base OS package changes. Follow
[Docker's digest-pinning guidance][docker-pinning], with explicit security refreshes.

Choose one workspace layout inside both executions; qualify all source-path-dependent
lookups. Resolve the digest in a trusted preparation step before starting the suite;
if a GitHub job container is used, its configuration must resolve the same locked
reference. Do not assume a step can retroactively change its job's container image.

## 5. Build profiles: share only when equivalence is demonstrated

The following is a migration partition, not a claim that these inputs are already
normalized or that different rows can share linked binaries:

| Family | Distinctions present in source | Initial reuse decision |
| --- | --- | --- |
| Strict | Clang 21, Release, Werror, jemalloc, LLD, `x86-64-v2` and PORTABLE | Own profile; retain the whole-tree warning gate |
| Branch chain | Clang 21, Release, production ON, jemalloc, `x86-64` | Not the strict profile; preserve full native fixture and real chain |
| Contract/auth baseline | Root Release build, host-default compiler, contract generators and emulator | Share only after compiler, CMake flags and generated-input closure agree |
| Falcon x86 | QUIC ON, bundled OpenSSL, `TOSLIBJSON_STATIC=OFF`, native tools plus Cargo release | Dedicated producer; additional node targets extend the same build tree |
| Falcon ARM | QUIC OFF, system OpenSSL, no x86 live-chain step | Separate platform/profile; not equal-work timing evidence |
| ASAN families | Instrumented compiler/linker settings and suite-specific targets | Separate instrumented builds; preserve both sanitizer workflows |
| Admission | Explicit distro `clang`/`clang++`, Release, its own native boundary targets | Do not silently substitute Clang 21; normalize only in a reviewed profile change |
| Quantum readiness | Release, QUIC OFF, system OpenSSL, real genesis/config targets | Not interchangeable with QUIC-enabled branch-chain artifacts |
| Rescue parity | Native Release plus Cargo **debug** drivers and changing native-signer/vault features | Distinct Rust feature/profile identities; mutation copies are exclusive |
| Mobile crypto | Separate `sdk/native/quantum` project; Linux x86/ARM and macOS; Rust debug tests and release C ABI library | Keep small project and cross-platform cells, not a full-node build dependency |
| Python/JS/Rust-only | Locked dependency graphs, generated bindings and explicit feature/target selection | Dependency caching separate from native artifact production |

The current native-cache CPU/OS/compiler identity is deliberately conservative.
Do not drop its CPU identity while `-march=native` or host-dependent code generation
is possible. Explicit architecture floors may permit broader sharing only after
compilation and runtime probes establish compatibility.

A producer fingerprint must include source identity, image/platform, CMake project
root, compiler/linker identities, optimization/sanitizer/architecture options,
feature flags, relevant lockfiles and generated inputs. Consumers also bind fixture
and execution-contract identities. Cargo feature unions can change behavior: do not
combine `native-wallet-signer` and `native-wallet-vault` merely to avoid another build.

### Object caches are not artifact identities

Object caching may span candidates because the compiler cache validates compilation
inputs. A finished binary bundle is consumable only for its exact producer identity.
The current preparer leaves `CCACHE_SLOPPINESS` empty and avoids restoring arbitrary
cache configuration; retain that policy.

Do **not** globally introduce `CCACHE_BASEDIR`. The native-cache implementation
specifically excludes it because rewritten `__FILE__` paths broke library/test-data
lookup. The strict workflow has its own existing setting; migration must test both
behaviors rather than assume one setting is universally correct.

Cache trusted and untrusted execution separately. Do not grant release builds access
to an untrusted PR's writable caches. Use bounded capacity and eviction, and report
cold misses, warm hits and cache upload/download costs. A restored cache entry must
not let changed headers, warnings or compiler flags evade recompilation.

## 6. Reduce repeated builds without losing parallelism

Start with compatible object caches, preinstalled dependencies and shared entrypoints.
Then group targets needed by independent consumers under one baseline producer **per
candidate and compatible profile**, not one build for the entire repository.

A producer exposes an immutable manifest and the binaries/libraries/generated files
consumers actually need. Consumers verify source/profile/image/manifest identity and
run fresh tests. Measure transport time and archive size; a huge uploaded build tree
can cost more than a local cached rebuild. Do not reuse a CMake/Ninja directory at a
new path without addressing embedded paths, RPATH and runtime dependencies.

GitHub `needs` shares a graph only inside a workflow. A reusable workflow does not,
by itself, share a build across otherwise independent workflow runs. Stage one keeps
the existing workflows and improves their compatible caches. A later graph migration
must explicitly implement producer/consumer artifacts, or co-locate those tasks in
one reviewed workflow while preserving check identities and result meaning.

Do not replace all workflows with a serial mega-job. The objective is lower **critical
path and total CPU work**, not fewer YAML files at any cost. Small checks should fail
before expensive compilation where independent; mutation jobs should not block
unrelated read-only consumers of an already frozen healthy baseline.

### Mutation and live-fixture isolation

For each mutation worker, create a separate source snapshot and writable build tree.
Never concurrently run deletion controls against a shared checkout or Ninja/Cargo
output directory. A worker may read verified normal artifacts as a starting point,
but must rebuild affected targets for its mutation. Its modified outputs are never
published as the normal baseline producer.

The receipt must distinguish baseline pass, successfully built mutation, failure for
the intended runtime reason, restored-source build and restored pass. Build errors,
missing fixtures and skipped tests are not successful guard-removal evidence. Verify
tracked and generated source identities after restoration and before exporting results.

Each live test has its own private network, ports, runtime directory and public test
keys. Quantum version-18 candidate data and Falcon version-19 data are different
fixtures; never substitute one merely because both need a local validator process.

## 7. Source and event identity: pre-push is not GitHub's future merge commit

Record the following per run:

```text
repository, event, PR number, head H, base B, observed test-merge M,
actual tested commit S and tree, suite/contract revision,
image digest/platform, build fingerprint, fixture identity, attempt, result
```

Several #138 workflows explicitly check out H: admission, rescue, readiness, mobile
and Falcon. Normal PR checkout in branch-chain tests the synthetic integration
commit. Preserve these modes during extraction; do not label every suite "merge-tested"
because it was started from a PR, or label a source-head receipt as integration evidence.

Before pushing, test the clean local commit and construct an integration candidate
against an explicitly fetched base in a **disposable clone/worktree**. Its commit ID
need not equal the later GitHub synthetic merge ID; compare integrated tree identity
and record this as **local integration preflight**, not hosted qualification. After a
push, fetch and verify the actual permitted merge ref and run the applicable hosted
checks. If H, B, M, image or contract revision changes, retire stale qualifying results.

The local adapter needs explicit event/branch/base information for changed-line hygiene
and conditional suites. A missing base must not silently select zero tests. Dirty-tree
quick checks are useful, but need a dirty content digest and cannot be represented as
results for the last commit. The phase-zero inventory intentionally reads committed
objects only and has a test proving that dirty files do not change that report.

Keep every-branch-push coverage in `branch-chain-python.yml`: its source comments make
this a deliberate safety boundary. A head push and an integration PR run are not
necessarily duplicates. Any future coalescing needs both trigger coverage and tested
source identity evidence, not just matching PR numbers. See [PR event semantics][pr-events].

## 8. Coverage ledger and fail-closed results

Planned local modes:

| Mode | Meaning |
| --- | --- |
| Fast | Advisory changed-boundary checks plus their dependencies; never replaces qualification |
| Full Linux x86 | Every cataloged applicable Linux x86 suite, including mutation/live boundaries; other platforms explicitly outstanding |
| Platform qualification | Native ARM/macOS/Windows and provider-specific checks on suitable workers |

Do not ship a `full` command that silently runs only the suites already ported. An
unmapped job, unknown condition, missing image, incomplete matrix or unavailable fixture
must produce `blocked` or `not_implemented`, not a green aggregate. Distinguish `passed`,
`failed`, `cancelled`, `timed_out`, `not_applicable`, `remote_required` and `blocked`.
Non-applicability must have a recorded reason tied to the event and policy.

Every migrating job gets a coverage row linking its old workflow/job/matrix/step to
its new script and expected tests, controls and artifacts. Use CTest registration
checks and `--no-tests=error`; also reconcile the expected set, since that flag alone
cannot detect one missing test among many. Preserve Cargo package/features and
integration targets, `--no-fail-fast`, required `--ignored` cases, full Python suite
scope and exact-count assertions for real engine reads. Do not replace execution
with a successful compile.

The future semantic inventory must understand workflow and composite/reusable-action
references, matrices (including include/exclude), job/step conditions, permissions,
events and ordered path filters. A regex or YAML 1.1 parser that treats `on` as a boolean
is not sufficient. Unsupported semantics require review rather than an inferred pass.
The delivered byte inventory deliberately makes none of these semantic claims.

### Preserve existing branch protection

The main branch summary returned these required contexts, associated with GitHub
Actions application ID `15368`:

```text
hygiene
strict-build
source-guards
rust-format
native-registry-reproducibility
python-and-pq-chain
rust-workspace-tests-compile
```

That read is not an administrative audit of every ruleset. Before any gate migration,
re-read effective protection and verify the actual produced check names and source
commits. This PR changes neither protection nor those identities. Do not replace an
Actions-owned required check with an unauthenticated local status of the same name.
A wrapper must propagate failure, cancellation, missing evidence and skipped
prerequisites; `always()` followed by unconditional success is not a gate.

## 9. Quantum-specific acceptance cannot be optimized away

Retain all eight changed/new workflow boundaries in section 2, including the existing
classic wallet baseline and independent native/Rust execution. Keep both required
architectures; retain asymmetric controls where the original matrix intentionally
runs them only on x86. Preserve evidence retention (including the admission suite's
90-day artifact policy) or separately approve a replacement with equivalent access.

H20 tree construction is not ordinary compilation. Do not cache mutable LMS signing
journals, enrolled state, custody directories or fee-leaf counters between cases.
A read-only, deterministic **public** test fixture can be reused only with a declared
identity and independent fresh mutable state; generated test keys are never operational
wallet or validator keys. Crash, restore, competing-process and no-leaf-reuse tests
must retain their actual state transitions.

The `quantum-mobile-native` workflow tests a small native API, Rust fee state and C ABI.
It is not proof of complete Android/iOS application creation, proof acquisition,
independent custody, funded POP, rotation, delivery and device lifecycle. Those release
acceptance boundaries remain separate. Likewise a successful hosted suite does not
close every outstanding T01-T28 requirement in #138's completion inventory. This CI
project must not alter wallet defaults, gas policy or release activation to make tests
cheaper.

## 10. Protect the development/validator host

Old descriptions of 192 cores, 125 GB RAM and disk utilization are author-reported
historical data, not a present capacity assessment. Measure available CPU, memory,
disk/I/O and validator latency under current load before selecting a worker budget.
Start with one admitted heavy pipeline; increase only from measured headroom.

The executor must enforce aggregate CPU, memory, process and disk limits, including
nested CMake, Cargo, linker, Python and signer subprocesses. Setting only Ninja `-j`
is not sufficient, and running every workflow with `nproc` is not a resource plan.
Record peak RSS, cache/artifact growth and time spent waiting for resource admission.

Use a dedicated CI identity with rootless containers where supported. Mount only its
source snapshot, bounded cache and output directories. No home directory, SSH agent,
validator data/keys, Docker socket, host networking or privileged mode enters a job.
Use disposable private networks and make cancellation tear down the whole process
and network group. Dependency acquisition may need outbound access; execution should
use the smallest explicitly declared network access after preparation.

This is trusted internal development CI, not a hostile-code isolation guarantee.
Unreviewed forks or imported code need a separate disposable VM/worker trust domain.
Do not run arbitrary repository code alongside funded keys merely because a Dockerfile
exists. Image promotion and any future GitHub result publisher keep write credentials
outside the job. No new host service is installed by the current proposal.

## 11. Migration work packages and go/no-go criteria

| Phase | Deliverable | Exit condition |
| --- | --- | --- |
| P0, this PR | Pinned B/H directory inventory, offline drift CLI and its tests in existing cache-validation job; this design | Tree IDs reproduce; malformed/empty/drift inputs fail; deliberate guard removals fail tests |
| P1 | Full job/matrix/step/evidence ledger; shared strict/hygiene/source entrypoints; reviewed image promotion/lock | Same commands and inputs shown in local/hosted runs; no tool-pinning, compiler or gate drift |
| P2 | Compatible caches and baseline producers for main's expensive suites, starting with measured cache gaps | Cold/warm/header-change/flag-change probes; equal coverage; no shared mutation directories |
| P3 | Port all #138 boundaries on the actual integrated main | Version18/19 fixture distinction, features, native/Rust controls, state isolation and platform obligations preserved |
| P4 | Safe fast selection and producer/consumer graph consolidation | Complete old-to-new ledger; shadow runs and seeded failures agree; required-check propagation verified |
| P5, separate decision | Optional self-hosted Actions or private Forgejo scheduling | Admission, host isolation, credentials, exact-source publication and capacity accepted separately |

P1 can begin on main without stacking CI changes on the wallet branch. P3 cannot use
an old head as evidence for a newly integrated tree. Each phase is a bounded PR with
its own validation; do not bundle image changes, compiler normalization, test selection
and required-check removal into one unreviewable migration.

For shadow comparison, exercise both passing and deliberately broken candidates:
changed native header/warning, incompatible image/architecture/profile, omitted
registered test, empty report, ignored-test omission, stale source/base, interrupted
mutation, missing artifact, timeout and cancelled dependency. Record whether each
failure is the expected assertion rather than preparation failure. Code generation
and contract artifact checks must still fail on stale output.

### Measure the bottleneck, not a prettier duration total

For each exact suite/profile/source, collect queue/admission time, environment setup,
configure, compilation, linking, test execution and artifact publication separately.
Report cold and warm runs, cache hit/miss counts, total CPU work, peak memory/disk,
critical-path wall time and eventually P50/P95 over a stated sample size. Summing
parallel job wall times is not either critical-path latency or CPU work.

Use immutable run IDs/attempts and export step timings before prioritizing work.
Compare identical coverage; Falcon ARM and x86 are not like-for-like because the live
node step and crypto dependencies differ. The old memo's 15-25 minute goal is not a
measured guarantee and is not adopted as a promise here. Initial acceptance requires
no coverage loss and a demonstrated improvement on the measured bottleneck; quantify
the target only after a reproducible current baseline exists.

Rollback restores the previous reviewed entrypoint/image/profile and leaves hosted
gates active. Do not disable a failing test or relabel an incomplete run successful
to achieve the performance target.

## 12. Delivered phase-zero tooling and reproduction

These commands exist in this PR and need only Python 3.10+ and local Git for the
repository comparison. They do not require Docker or repository native dependencies:

```sh
python3 scripts/ci_workflow_inventory.py \
  --verify-baseline doc/ci-local-first-baseline.json
python3 scripts/test_ci_workflow_inventory.py -v
```

`--verify-baseline` checks metadata shape, duplicate JSON keys, directory object
identities, file modes, counts and the change list. It prints `ci_result: null`.
It does **not** independently prove a commit-to-tree relationship without that commit
object, parse workflow semantics or test a build. The baseline commit-to-tree bindings
were obtained from the GitHub API; directory hashes were independently reconstructed.

With B and H available in a non-promisor local repository, verify that binding too:

```sh
python3 scripts/ci_workflow_inventory.py --repo . \
  --base b121f3a45366d8d8516ffa61923312c05accb64d \
  --candidate 99ec7e18299c78a944ca83f4e041dbf374a2dcf8 \
  --expect doc/ci-local-first-baseline.json
```

Fetch required objects separately through the developer's normal authenticated Git
setup. The CLI never checks out or executes either candidate. It refuses local
promisor configuration, ignores Git replacement objects and rejects absent workflow
evidence. It records complete direct directory entries, including nested tree IDs;
only direct ordinary `.yml`/`.yaml` files count as workflows. Symlink workflows are
refused rather than silently counted.

To inspect a later pair, use `--base` and `--candidate` without `--expect` and review
the report. To enforce a frozen review basis, add `--expect`: exit **1** means source
or workflow-tree drift; exit **2** means invalid/incomplete inputs; exit **0** means
only that the requested inventory operation succeeded. Source-only commit changes
also invalidate an expected report, even when workflow bytes are unchanged.

Do not automatically replace the baseline with whatever currently passes. This
committed baseline is the historical design input, not a required equality between
future main and an old feature branch. The existing cache-validation job runs the
metadata/self-tests, not an assertion that future main must stay at B or H.

### Validation performed for this proposal

The inventory test suite ran against real disposable local Git repositories:
**26/26 passed**, including add/remove/content/mode changes, tabs/Unicode names,
nested tree sorting, missing references, empty evidence, symlinks, dirty-tree isolation,
replacement-object isolation, promisor refusal, JSON tampering and both CLI modes.
The B/H metadata reconstructed both API directory IDs exactly (50/54 files; 4/4 delta).

Five guard-removal experiments were syntax-checked and each produced the intended
unit-test assertion failure; the intact suite passed again after restoration:

| Removed behavior | Targeted `InventoryTests` test(s) |
| --- | --- |
| `--expect` drift refusal | `test_cli_workflow_drift_fails`, `test_cli_source_only_movement_fails` |
| Zero-workflow refusal | `test_no_workflow_files_is_not_success` |
| Directory-hash consistency comparison | `test_tampered_tree_refused` |
| Mode component in modification comparison | `test_mode_only_change_is_not_hidden` |
| Both replacement-object suppression mechanisms | `test_replacement_commit_cannot_change_snapshot` |

Reproduce a targeted control in a disposable copy: remove only the named behavior,
run `python3 scripts/test_ci_workflow_inventory.py InventoryTests.<test> -v`, require
an assertion failure (not a setup error), restore the original script, and rerun all
26 tests. For the last control remove both `--no-replace-objects` and the
`GIT_NO_REPLACE_OBJECTS` environment entry; merely assigning the latter `"0"` does not
remove Git's replacement suppression.

The cache-validation workflow edit only widens its path filters for the new tool/test/
baseline and adds their test step. Existing cache tests, action pins, permissions,
job identity and concurrency are retained. Removing those additions reproduces the
original workflow blob `7e2dbf336e17b0142368292038bc99e22077619d` exactly.

No full TOS build, actual B/H repository checkout comparison, Docker build, ARM/macOS
execution, local/hosted equivalence benchmark, effective protection migration or
validator-host load test was performed here. The container did not have a source
checkout or Docker; source inspection used the connected GitHub API. These remain
explicit later-phase acceptance items, not implied successes. Hosted CI for this PR
must report its own result independently.

## References

[main]: https://github.com/tosnetwork/tos/tree/b121f3a45366d8d8516ffa61923312c05accb64d
[head]: https://github.com/tosnetwork/tos/tree/99ec7e18299c78a944ca83f4e041dbf374a2dcf8
[pr138]: https://github.com/tosnetwork/tos/pull/138
[head-workflows]: https://github.com/tosnetwork/tos/tree/99ec7e18299c78a944ca83f4e041dbf374a2dcf8/.github/workflows
[builder]: https://github.com/tosnetwork/tos/blob/b121f3a45366d8d8516ffa61923312c05accb64d/Dockerfile.builder
[builder-workflow]: https://github.com/tosnetwork/tos/blob/b121f3a45366d8d8516ffa61923312c05accb64d/.github/workflows/build-builder-image.yml
[strict]: https://github.com/tosnetwork/tos/blob/b121f3a45366d8d8516ffa61923312c05accb64d/.github/workflows/build-tos-linux-x86-64-werror.yml
[native-cache]: https://github.com/tosnetwork/tos/blob/b121f3a45366d8d8516ffa61923312c05accb64d/.github/actions/native-cache/prepare.py
[falcon]: https://github.com/tosnetwork/tos/blob/99ec7e18299c78a944ca83f4e041dbf374a2dcf8/.github/workflows/wallet-falcon.yml
[forgejo-plan]: https://github.com/tosnetwork/memo/blob/main/ci-local-forgejo/README.md
[act]: https://nektosact.com/not_supported.html
[job-containers]: https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/run-jobs-in-a-container
[docker-pinning]: https://docs.docker.com/build/building/best-practices/#pin-base-image-versions
[pr-events]: https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request
