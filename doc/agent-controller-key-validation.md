# Agent controller stored-key validation

## Finding and correction

The stored-controller-key omission was present at `994ac69cfb854fbb9d43535f81498c28993eae9c`.
`process_controller_request` called `require_strong_controller_key` only for a raw
`agent_checked_contract_call_v2` request. The legacy task, native transfer,
cancellation and deployment operations could reach `check_signature` without the
same check. A deliberately weak stored key can make signature verification an
insufficient authorization boundary. This is not a private-key recovery attack
against normally generated controller keys.

The correction calls the existing guard inside the common `ifnot (via_module)`
signature branch, before hashing/verifying the signature and before either
`accept_message` call. The weak-key policy, operation encodings, network binding,
controller epochs, seqnos, expiry checks, value policies and post-accept commit
semantics are unchanged. The obsolete v2-only guard is removed.

Do **not** move this guard into `load_agent_state`: a legacy/staged owner must
still be able to recover a malformed account by rotating its weak controller to
a strong key. Owner authentication and replacement-key validation remain in the
rotation path. Module-only execution does not depend on the legacy key; hybrid
execution still requires the installed module plus a valid strong-key
cosignature. Strict modes cannot reopen raw legacy authorization.

SDK creation already rejects weak keys. Hand-built StateInit and historical or
incorrectly initialized state still need the on-chain boundary. The regression
therefore deploys its intentionally malformed fixtures through real StateInit
messages instead of relying on the SDK to create forbidden state.

## Changed release identity

The FunC source and the Rust `AGENT_ACCOUNT_CODE_B64` embedding are updated
together. The SDK's frozen code-hash and deterministic StateInit/address tests
are updated, not removed. `scripts/update-auth-contract-code.py --check` verifies
all embeddings without rewriting the working tree. The C++ envelope is generated
from the same source by the existing CMake `GenFif` dependency.

| Identity | Before | After |
|---|---|---|
| Code cell hash | `efc5675d718c3172f65c87ecef648beb6a2f6e2046099883ccccf03683051620` | `53600f89a4849412001f3c075b8f02fe2845ff6de60866fb65dc2b6b98fa1dd1` |
| SDK `valid_init` StateInit hash | `b9b9997179f55b800ab7f3a2d3ba9af7dd2aaa52d2d6537ee22d7f89bee1b953` | `c28f0b1e3ea4c26a6aec5ebab4a317da8493d229a2c88fd724705ef1ae5b4929` |

Changing the SDK constant does not upgrade an already deployed contract. New
deployments use a different code hash and consequently different deterministic
addresses. Existing legacy/staged weak-key accounts need their authenticated
owner to rotate to a strong controller; this cannot recover value already sent
away. Strict-mode recovery remains subject to the installed module/hybrid
policy. No live-account inventory, production deployment or migration is claimed
by these tests.

## Native evidence and sensitivity

Validated production changes: `a3738e75ed2d2b057121980ba0aac5e8894b2a33`.

Run `38524297142` contains the successful native job and a separately reported
Rust SDK/sandbox job. Its `agent-controller-validation` artifact includes the
exact committed source, native results, existing-agent authentication results,
and a semantic-red receipt. The bootstrap workflow's head is an earlier setup
commit; `source-commit.txt` binds its tested working tree to the production
commit above. The one-time bootstrap is not part of the final change.

- Native artifact ID: `11875158311`.
- Archive SHA-256: `92521afe5349d9de3d82f709dba415d64efab2d75fdac2a026651ffc2e3695f9`.
- Archive size: 11,125,489 bytes; retained until 2026-11-13. The archive includes
  the formatter used during preparation as well as the small evidence files.
- Retrieval: `gh run download 38524297142 --repo tosnetwork/tos -n agent-controller-validation`.
- The ordinary authentication workflow now reruns the new regression and keeps
  its `results.json` for 30 days. The test and reproduction commands remain in
  Git after transient run artifacts expire.

The 12 native test methods run on workchains -1 and 0 with real signature
verification, actual deployment transactions and a real action phase:

| Boundary | Coverage |
|---|---|
| Weak stored key | All 48 encodings in the existing policy, legacy/staged, all five signed operations, both workchains, two attempts each: 1,920 pre-accept refusals at 1720 |
| Causal control | Identity and order-2 sign aliases, both modes/workchains: eight no-secret transfers succeed with the guard restored to v2-only; the fixed code rejects them; v2 stays protected in both versions |
| Strong controller | 20 operation/mode/workchain cases; wrong-key signature rejected, valid signature accepted, replay rejected |
| Owner recovery | 192 weak-key/mode/workchain cases; unauthorized caller and a different weak replacement rejected, strong replacement accepted, new controller can subsequently sign |
| Module boundary | Staged/module-only execution, wrong sender, replay, strict downgrade, hybrid weak-key cutover, raw-owner bypass, module-authorized recovery, missing/invalid hybrid cosignatures |
| Actual value movement | Emitted messages are delivered to recipient contracts; sender/recipient data, transferred value, transaction fees and outstanding forward fees reconcile exactly |

The baseline uses the same forgery construction at each code's actual StateInit
address, not an impossible in-place substitution of deployment code. The
order-2 control selects an admissible expiry with the necessary reduced-challenge
parity. Not all rejected encodings are claimed to be exploitable in every native
verifier: some canonical weak keys are already refused by the backend. The
accepted aliases establish why the contract-level check is necessary.

The preparation also ran the weak-key rejection test with its compiled code
replaced by the legacy-only mutant. Both legacy/staged assertions failed on
**accepted native transactions**, with no compile/setup errors. Separately,
13 existing Agent Account authentication tests and both existing native alias
tests passed. Those include the actual signed-module relay and policy, epoch,
nonce, overflow and post-accept replay boundaries.

## Admission gas

The regression fixes VM global version 16 and a 10,000 external gas credit in
both ConfigParam 20 and 21, including on profiles that permit a larger basechain
credit. This is an explicit test configuration, not a claim that a complete live
network configuration was reproduced. Both metadata hashes and staged AUTH
state are present in the larger profiles. For every row, a binary search checks
that credit G succeeds and G-1 fails for gas rather than signature/setup errors.

| Operation | MC legacy | MC staged | Basechain legacy | Basechain staged |
|---|---:|---:|---:|---:|
| Task send | 8,347 | 8,525 | 8,609 | 8,787 |
| Native send | 8,448 | 8,626 | 8,710 | 8,888 |
| Cancel | 6,946 | 7,124 | 6,946 | 7,124 |
| Deploy send | 8,948 | 9,126 | 8,948 | 9,126 |
| Checked call v2 | 9,017 | 9,195 | 9,279 | 9,457 |

These are measured **minimum admission credits** for the committed corpus, not
full-transaction gas totals or a formal all-payload worst-case proof. The largest
measured value leaves 543 gas under the unchanged 10,000 credit. No production
gas configuration, crypto tariff or authentication ordering is weakened.

## Reproduction and continuing gates

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target func fift tol emulator -j2
export FUNC_PATH="$PWD/build/crypto/func"
export FIFT_PATH="$PWD/build/crypto/fift"
export TOL_PATH="$PWD/build/tol/tol"
export EMULATOR_PATH="$PWD/build/emulator/libemulator.so"
python3 -m pip install cryptography==46.0.4
python3 scripts/update-auth-contract-code.py --check
python3 test/weak-ed25519/test_agent_controller.py --output /tmp/agent-controller-validation
python3 test/weak-ed25519/test_native_aliases.py
python3 test/auth-extensions/test_auth.py
python3 test/auth-extensions/mutations.py
scripts/install-rust-toolchain.sh
cargo test --locked --manifest-path tosctl/src/Cargo.toml -p contracts --lib agent_account::tests
TOS_ROOT="$PWD" cargo test --locked --manifest-path tosctl/src/Cargo.toml -p contracts --test agent_account_sandbox
```

Changed-boundary gate mapping: FunC execution and recovery -> native regression;
shared AUTH behavior -> existing authentication and mutation tests; shipped
artifact -> regeneration check and native execution of the embedding; SDK
construction/identity -> Agent Account unit tests; Rust execution -> Agent
Account sandbox. The ordinary authentication workflow runs their union. A
passing preparation run is not permission to ignore a failing relevant PR check
or a branch-protection requirement.
