# Shared getter context: commit 1 validation

## Independent reference and unchanged replies

`getter-context-reference.h` contains the original `prepare_vm_c7` declaration and
body verbatim from `e7af7d3f8:validator/impl/liteserver.cpp`. Its SHA-256 is
`4cc2b04ab23188d56d8c881e91a139ba2073970442b611d12581423a7aad34dc`.
Fixture setup verifies that digest without requiring Git history in CI. The
reference draws its own secure seed; the extracted helper receives that seed.
It never calls the extracted helper.

`getter-context-before.tsv` was captured through the real, unmodified
`LiteQuery::run_query` handler before replacing its construction. It records
name, exit code, gas and complete base64 result BOC. The fixture combines a
generated masterchain state, the saved real elector account, two config proposals,
and a context-sensitive getter with a 101-bit balance, extra currencies and debt.
The response protocol has no gas field: gas comes from an independent execution
of the original VM initialization. The handler's exit code and full result BOC
are compared with that execution and with the pre-extraction capture.

| Getter | Exit | Gas before and after |
| --- | ---: | ---: |
| `participant_list_extended` | 0 | 7,456 |
| `active_election_id` | 0 | 1,408 |
| `compute_returned_stake` | 0 | 1,396 |
| `list_proposals` | 0 | 5,433 |
| context fields (`NOW`, `LTIME`, `BALANCE`, `MYADDR`) | 0 | 127 |

Additional checks compare every c7 field at versions 3, 4, 6, 9, 11, 14, 15 and
17, and without config; execute library-referenced code with present/missing
libraries across version 15; and compare basic and full exported c7 through the
actual handler (modes 12 and 44). Random exported seeds are normalized against the
independent reference; all other fields and the tuple shape must match.

## Reproduce the gates

From the worktree root:

```sh
env -u CCACHE_BASEDIR cmake -S . -B build -G Ninja \
  -DCMAKE_C_COMPILER=clang-21 -DCMAKE_CXX_COMPILER=clang++-21 \
  -DCMAKE_BUILD_TYPE=Release -DTOS_ARCH=x86-64-v2 -DPORTABLE=x86-64-v2 \
  -DTOS_USE_JEMALLOC=ON -DTOS_USE_LLD=ON -DTOS_WERROR_BUILD=ON \
  -DTOS_PRODUCTION_BUILD=ON \
  -DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
cmake --build build --parallel 8 --target create-state test-get-method-context \
  validator-engine test-vm test-proof-verify test-liteserver-admission
ctest --test-dir build --output-on-failure --no-tests=error \
  -R '^(getter-context-(context|vm|libraries|liteserver)|test-vm|test-proof-verify|test-liteserver-admission|lite-query-error-response-source)$'
CARGO_TARGET_DIR="$PWD/build/rust-target" RUSTC_WRAPPER=sccache \
  cargo test --manifest-path tosctl/src/Cargo.toml --workspace --no-run --locked --jobs 16
cargo fmt --manifest-path tosctl/src/Cargo.toml --all --check
python3 scripts/check-branch-chain-python-ci.py
uv tool run ruff check test/validator/prepare-getter-context.py \
  test/validator/getter-context-mutations.py test/validator/getter-context-ci-controls.py \
  scripts/check-branch-chain-python-ci.py
git clang-format-21 --binary clang-format-21 --diff e7af7d3f8 -- \
  crypto/block/get-method-context.cpp crypto/block/get-method-context.h \
  test/validator/getter-context-fixture.h test/validator/getter-context-reference.h \
  test/validator/getter-context-test.cpp validator/impl/liteserver.cpp
git diff --check
```

All commands exited 0. Native CTests: 9/9, including fixture setup. The combined
parity executable reports 70 checks and zero failures. The production compiler
commands contain `-Werror`. No Rust production source changes; touched-crate
clippy and crate-specific tests are therefore not applicable to this commit.
The configured source does not consume `TOS_PRODUCTION_BUILD`; the option is
retained above to match the existing CI invocation.

## Reproduce each red/green control

```sh
python3 test/validator/getter-context-mutations.py --build build --jobs 10
python3 test/validator/getter-context-ci-controls.py --build build
```

For one production control, append `--only NAME` to the first command. For a
CI/oracle control, append it to the second. Each command creates a detached
worktree, verifies green, applies exactly the named replacement, requires exit 1
and the named assertion, restores the source, and verifies green again. A build
failure, fixture failure (exit 2), timeout, missing anchor or zero assertions is
an error. Primary source is never mutated. Native controls each have their own
Ninja target using the candidate's actual strict compiler flags; only unchanged
candidate dependency objects, archives and generated headers are shared.

The exact files, lines and assertions are in `getter-context-controls.json`.
The replacement strings are in the runners' `CONTROLS` / `CASES` maps.

| Name | Guard broken | Expected failing assertion |
| --- | --- | --- |
| clock | replace `make_refint(now)` with zero | `context-v3` |
| logical-time | replace both `make_refint(lt)` with zero | `context-v3` |
| seed | return zero instead of the seed | `vm-context` |
| balance | replace full balance with zero | `context-v3` |
| config | omit config root | `context-v3` |
| code | omit code | `context-v4` |
| previous | omit previous-block context | `context-v4` |
| unpacked | omit unpacked configuration | `context-v6` |
| debt | omit due payment | `context-v6` |
| precompiled | omit precompiled gas | `context-v6` |
| version | delay in-message context until version 12 | `context-v11` |
| account-library | admit account libraries at version 15 | `libraries-v15` |
| global-library | omit global libraries | `libraries-v14-global` |
| basic-export | export full context for basic c7 | `wire-c7-participants-12` |
| call-site | pass zero time in both handler calls | `liteserver-context-fields` |
| selector | remove handler test from CI selector | `getter-context independent parity gate is absent` |
| registration | remove handler CTest registration | `getter-context CTest registrations or fixture dependency are absent` |
| oracle | alter the frozen original clock field | `independent context oracle differs from the frozen source` |

Result: 18/18 intended refusals, every baseline and restored run green.

The production-context worst-case budget measurement belongs to commit 2 and
remains a hard merge gate. This commit introduces no control queries or executor
limits. No live services were restarted, redeployed or queried for this validation.
