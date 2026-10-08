# Shared CI execution and native coverage

Implemented on top of `fcd7f6bcab3f2d4fa4bddca96c0848af77fedc1a`, which
already includes the merged Quantum changes. The historical inventory in
`doc/ci-local-first-baseline.json` remains a frozen review snapshot; it is not a
requirement that future source equals that old snapshot.

## Implemented commands

```sh
ci/run list
ci/run preflight
ci/run source-guards
ci/run rust-format
ci/run native-registry
CI_BUILD_JOBS=8 ci/run strict-build
CI_BUILD_JOBS=8 CARGO_BUILD_JOBS=8 ci/run native
```

| Task | Boundary |
| --- | --- |
| `preflight` | Historical inventory consistency/tests, shared command contracts, real miniature CTest controls, workflow routing and container adapter tests |
| `strict-build` | Whole-tree Clang 21 Release/Werror; explicit x86-64-v2, jemalloc, LLD and ccache |
| `source-guards` | Configure, verify the exact source-guard inventory, execute the whole label with empty-selection refusal |
| `native-registry` | FunC/Fift, frozen registry, both staking code locks, node authority and generated-source cleanliness |
| `rust-format` | Existing repository-pinned Rust formatter |
| `native` | Linux shared build/install, complete registered CTest, full Python suite and targeted regressions, real chain/session integration, installed-library consumer |

The native phases are also independently callable as `native-build`,
`native-tests`, `native-python-env`, `native-python`, `native-integrations` and
`installed-consumer`. Hosted adapters call these same phases. Provision their
documented toolchain first; the native build installs the pinned Rust toolchain,
and the Python phase uses the frozen lockfile and generates the TL API.

**`native` is not all repository CI.** It does not replace the separate Falcon,
Quantum, security mutation, mobile, release or native non-Linux workflows.
Unknown `full`, `fast`, `all` and `quantum` aggregates fail, rather than claiming
an unimplemented qualification. `strict-build` passing is not a runtime test pass.
The integration runner's release-scenario `--help` is only a parse check.

## Coverage restored in hosted CI

Ten inherited Linux ARM, AppImage, macOS, Windows and WASM workflows now include
`main` in both PR-target and branch-push filters. Existing `master`/`testnet`
aliases, tag triggers, manual/reusable entrypoints, job IDs and runner identities
are retained. Full Linux shared execution is also pre-merge and includes both
Ubuntu 22.04 and 24.04. No path-based test skipping was introduced for these lanes.

The five shared profiles retain their out-of-tree consumer test against
`build/install`; compiling the library inside the source build is not a
replacement. The six packaging uploads fail when no files are found. Existing
exact-source release collection/provenance checks are unchanged. Windows batch
build failure now exits before another command can mask it; Windows CTest remains
commented out, not represented as runtime coverage.

`ci/native_tests.py` inventories the *configured* CTest registry and executes it
without a selector. Every registered test, including additions beyond the
independent 13-test foundational floor, must produce exactly one successful
JUnit result. Missing/unbuilt/disabled tests, unexpected or duplicated results,
skips and nonzero CTest exits reject the run. Old success receipts are removed
before a new attempt. Records live in `build/ci-native-results`. They describe
that local execution, not signed source/image attestations.

The retained source-guard inventory and security suites complement this floor.
A floor cannot prove that every possible future registration still exists:
changes to registration or supported profiles still require coverage review.

## Actual reuse and setup reductions

Native Registry and Falcon use the existing CPU/OS/compiler-aware native cache.
Falcon also uses a pinned Rust dependency cache, keyed by architecture and host
identity. Its test/mutation/sanitizer/live-chain/parity run blocks are preserved;
cache hits never skip tests. Mutable signer, LMS, fee or custody state is not a
cache. The AppImage x86 restore prefix now matches its timestamped saved entries.

Python-only hygiene changes no longer install Clang formatting tools. Python and
whitespace checks remain enabled. Shared command failures stop the task even
when invoked from a `sh` caller. Strict and Registry jobs run the cheap
infrastructure checks before expensive work.

These changes reuse compilation objects/dependencies, **not linked binaries
between incompatible jobs**. Native-script worker limits are explicit, and
compiler cache size is bounded. Restoring previously missing main coverage adds
real work; a net speedup over the old incomplete coverage is not claimed.
Measure cold/warm times only at equal coverage.

## Local Docker adapter

Use a dedicated credential-free clone with its own `.git` directory, not a linked
worktree. Build the existing builder target or select a reviewed registry digest:

```sh
docker build --target builder-24 -f Dockerfile.builder \
  --iidfile /tmp/tos-ci-builder.id .
CI_BUILD_JOBS=8 CI_DOCKER_MEMORY=16g \
  ci/docker "$(cat /tmp/tos-ci-builder.id)" native
```

Use `builder-22` to exercise Ubuntu 22.04 userspace. A reviewed
`ghcr.io/tosnetwork/tos-builder@sha256:<64-hex-digest>` is also accepted.
Mutable tags are refused. The current builder includes pinned Clang/uv and
ripgrep; it contains x86-specific tools, so this adapter refuses non-native
Linux x86_64 rather than calling emulation parity.

The adapter uses an ephemeral HOME and persistent dedicated Cargo/Rustup/uv/ccache
directories, a read-only container root, host UID/GID, dropped capabilities,
no-new-privileges, PID/CPU/memory limits and a temporary filesystem. It does not
mount the Docker socket or select host networking. The source checkout is writable
because builds generate fixtures and need Git metadata. Check that it contains no
credentials, wallets or production state. A custom `TOS_CI_CACHE_DIR` must contain
only disposable caches. This is not a security sandbox for hostile code; use a
separate disposable VM for untrusted contributions, never a validator/key host.

Use separate checkouts for strict, shared and system-compiler Registry builds.
A profile marker rejects incompatible or unowned existing CMake build directories.
It does not serialize simultaneous executions: never run concurrent mutation or
chain suites in one checkout. The default local limit is 8 workers and 16 GiB;
choose limits for the host, and leave resources for other workloads.

**Environment parity remains bounded.** Hosted shared jobs still resolve their
existing builder tags and install the source-search dependency. Local immutable
images do not prove those hosted tags resolve to the same digest. Image promotion,
hosted digest locks and cold/warm runtime parity require separate evidence before
claiming byte-identical environments. Kernel, architecture and privilege behavior
are not made identical by Docker. No daemon/full-build test was run in the editing
container.

## Verification and qualification

```sh
ci/run preflight
python3 scripts/test_ci_entrypoints.py -v
python3 scripts/test_ci_native.py -v
python3 scripts/test_ci_docker.py -v
bash -n ci/run ci/docker assembly/native/build-ubuntu-shared.sh
```

The new suites contain 27, 23 and 6 tests respectively. They execute the real
scripts with recording/failure stubs and real miniature CMake/CTest registries;
they are not full project builds. Deletion controls for the core-test floor,
exact result set, run status, stale success removal, main routing and missing
artifacts all reject; restoring the code restores the pass.

See `doc/ci-refactor-validation.json` for the bounded result index. Hosted lint,
cache contracts and affected native/platform gates must establish their own
results on the published commit. Pending jobs are not passes. No branch-protection
change, release publication, main merge or validator-host installation is part
of this change.

Remaining qualifications include hosted image digest promotion, actual full
platform results, a separately qualified second compiler, Python typecheck debt,
exact producer asset manifests beyond non-empty uploads, old branch-image
publication policy, and a complete all-workflow local execution catalog.
