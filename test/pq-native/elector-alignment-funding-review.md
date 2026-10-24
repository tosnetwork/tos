# Elector alignment review: pool funding and signing-tool tests

Reviewed input: `b8e4094f45a6d34cbe8f23d13476f8e5d359468f`.
Base: `df37dac548eb8641f9c5bde3d478774b94adc30a`.
Local upstream reference: `857b8a57a178e6ae0fe7fa86e7d81c5233de8560`.
Host: macOS arm64, repository-pinned Rust 1.97.1, fresh native Release build.
The source hashes below identify the repaired files in this commit.

## Findings and repair

- P1, PA-4/SC-2: the election runner puts the requested net stake directly in a
  multi-nominator pool order. That pool forwards the exact order value, and the
  Elector subtracts one TOS for its confirmation. With a 10,000 TOS minimum, the
  minimum policy submits 9,999 TOS net and is refused with reason 5. Account for
  that allowance in both the order and available balance. The same balance path
  also inherited a one-TOS storage reserve for every pool, although the multi
  pool requires ten; use the pool-specific reserve before applying the policy.
  Checked addition refuses overflow before a wallet message. Submission records
  retain the requested net amount. Single-nominator and direct-wallet semantics
  are preserved; no contract bytecode changes are part of this repair.
- P2, TE-1/PA-4: the registered signing integer test still requires the removed
  controller executable and passes the old stake argument list. Its actual CTest
  invocation exits at argument parsing, as also observed in strict-build CI.
  Remove obsolete cases and exercise all three remaining commands, retaining
  rejection-before-key-access and valid wire-width boundary coverage.

## Reproduction and results

Use the native binaries from the reviewed checkout, not an older main build:

```sh
export PATH=/opt/homebrew/opt/coreutils/libexec/gnubin:$PATH
export TOS_ROOT="$PWD"
export FUNC_PATH="$PWD/build-review/crypto/func"
export FIFT_PATH="$PWD/build-review/crypto/fift"
export CREATE_STATE_PATH="$PWD/build-review/crypto/create-state"
export PQ_VOTE_TOOL="$PWD/build-review/crypto/tos-pq-vote"
# PQ_KEY_TOOL points to the existing tos-pq-key fixture generator (unchanged source).
export PQ_KEY_TOOL="$TOS_ROOT/build-pq-key/tos-pq-key"
export CARGO_TARGET_DIR="$TMPDIR/tos-review-target"
cargo test --manifest-path tosctl/src/Cargo.toml --locked -p elections -p contracts --lib --no-fail-fast
cargo test --manifest-path tosctl/src/Cargo.toml --locked -p contracts --test elector_sandbox --test single_nominator_sandbox --test nominator_pool_sandbox --test pq_validator_lib_sandbox --no-fail-fast
ctest --test-dir build-review --output-on-failure -R '^(pq-stake-auth-response-source|tosctl-pq-stake-builder-source|tosctl-election-chain-reads-source|stake-authorisation|authorisation-preimage-vectors|pq-signing-tool-integers)$'
FUNC_BIN="$FUNC_PATH" FIFT_BIN="$FIFT_PATH" bash scripts/check-nominator-pool-code-lock.sh
FUNC_BIN="$FUNC_PATH" FIFT_BIN="$FIFT_PATH" bash scripts/check-single-nominator-code-lock.sh
```

| Check | Result |
| --- | --- |
| elections / contracts unit tests | 54 / 288 passed, exit 0; one child-process helper marked ignored (invoked by its parent restart test) |
| Elector / single pool / multi pool / PQ library sandboxes | 81 / 8 / 6 / 7 passed, exit 0; one Elector profiling test ignored |
| Native authorisation and preimage vectors | 2 passed, exit 0 |
| Three registered source guards above | 3 passed, exit 0 |
| Pool bytecode locks | both passed, exit 0 |
| Signing integers | 136 invalid cases refused and 30 valid signing cases passed, exit 0 |
| Contract guard mutations | 27/27 detected; baseline and restored tests passed, mutant tests failed |
| Rust formatting, changed Python lint/format and whitespace | passed |

Sensitivity: keep the four new `a_multi_pool_` tests but replace the production
wrapper, multi-pool implementation and runner with the input revision's files.
`cargo test --manifest-path tosctl/src/Cargo.toml --locked -p elections --lib a_multi_pool_`
then exits 101: **0 passed, 4 failed**. Restoring the repair gives four passes as
part of the 54-test suite. The failures cover the gross order, unfunded
confirmation, overflow, and the policy budget. The real pool-to-Elector test uses
1.2 TOS from the operator, sends 10,001 TOS from the pool, and asserts a recorded
net stake of exactly 10,000 TOS. Its 10,000-TOS negative control gets reason 5.
The original signing CTest exits 8 with `arguments are required: --controller`;
the repaired test runs the cases reported above.

The existing mutation harness was run unchanged except for selecting the native
build directory, with the same environment as above:

```python
import importlib.util, os, subprocess, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("guards", "test/pq-native/contract-guard-mutations.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
m.build = lambda: subprocess.run(["cmake", "--build", "build-review", "--target", "gen_fif", "-j4"], check=True, capture_output=True)
sys.argv = ["guards", "--out", os.path.join(os.environ["TMPDIR"], "pr284-contract-mutations.json")]
assert m.main() == 0
```

## Limits and baseline controls

- This is source, native signing and VM/action-phase validation, not a new live
  four-node deployment or an in-place upgrade of old controller storage.
- The full commands unit suite cannot compile on this macOS host: node-data-sync
  uses Linux-only libc APIs and platform-specific integer types. Both the input
  PR and exact base fail with the same nine diagnostics. It is not counted as a
  passing CLI suite.
- The shielded gas-ceiling test fails independently on both the reviewed input and
  exact base. `cargo test --release --locked --manifest-path
  tools/shielded-pool-circuit/crosscheck/Cargo.toml --test gas_ceiling_bound -j 6`
  exits 101 in both checkouts. The frozen ceiling is 1,510,000 versus a derived
  required ceiling of 1,380,000 in both; measured gas is 1,065,092 on the PR and
  1,064,934 on base. Only this failed target was replayed on base, not the entire
  workflow. This establishes the pre-existing assertion failure, not a green CI
  result or a security assessment of the shielded pool.
- Remote CI must be read again for the repair commit. Older runs and these local
  checks do not establish final Linux CI or authorize a merge.

Scratch logs are under `$TMPDIR/pr284-*` and have no guaranteed retention.
The bounded red/green results above and committed tests are the durable receipt;
raw logs and generated binaries are intentionally not committed.

## Repaired source SHA-256

```text
bdedea1a6e092a7e6f0e36b9ce857ba92721958c693922313847c38281695ab4  test/pq-mldsa44/signing_tool_integer_test.py
ae9b98da54dc4cef3d73f1132a241346f7f2738822b34b5e217fcfa2ead8fd4e  tosctl/src/node-control/contracts/src/nominator/wrapper.rs
2fbb04b68e278a9fee1f7d0fd5d2f1de66d2dc17e2aa16e6ac9f4eb94a4ad717  tosctl/src/node-control/contracts/src/nominator_pool/pool_impl.rs
a885c084847537bcef86b70e6da6bcb22517f42a72a47a2c4b46cdcba9e71d7f  tosctl/src/node-control/elections/src/runner.rs
aa70eff2e7c3674783a9357161d62fb5bf7f212e6672a25e07e42d8bda88b802  tosctl/src/node-control/elections/src/runner_tests.rs
3ac5b06597c301fc22e5d3fe2d70eff6f5fa2b141d0c80a6d3ff391263fe7f73  tosctl/src/node-control/contracts/tests/elector_sandbox.rs
```
