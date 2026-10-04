# Unified development protocol version 16

This branch consolidates the prelaunch VM feature allocations into protocol
version 16. Both the C++ node VM and Rust VM enable the following instructions
at 16 and reject them at versions 0–15:

| Instruction | Opcode |
| --- | --- |
| `PQCHECKSIG_MLDSA44` | `F93100` |
| `PQCHECKSIG_FALCON512_PADDED` | `F93101` |
| `POSEIDON2_PERM8` | `F93200` |
| `POSEIDON2_HASH7` | `F93201` |
| `POSEIDON2_PATH7` | `F93202` |

The frozen-account recovery rule already gated at 16 is retained. No opcode,
signature format, key derivation, domain tag, field parameter or gas tariff
changes. The byte-frozen privacy profile is preserved because its digest is
part of the pool's genesis identity.

Both binary capability ceilings, the canonical genesis template and the
harness genesis default are 16. PQ genesis refuses versions below 16. Local
PQ network tooling and the Falcon provider use the same baseline. Companion
Android and iOS branches named `codex/unify-protocol-v16` set both mobile PQ
profiles' minimum to 16; their previous signing PRs remain unchanged.

## Development-chain compatibility

Older development binaries interpret version 16 differently. ConfigParam 8's
number alone cannot distinguish those binaries. All validators and clients
must use this consolidated implementation. Start a fresh development genesis;
retained histories from earlier binaries require their original execution
rules. This source change does not alter any running network, reset a database
or implement a historical migration. Normal future consensus changes still
require a new protocol version after the baseline is frozen and launched.

## Reproducible validation

Build `emulator`, `test-poseidon2`, `test-pq-falcon512-parity`, `func`, `fift`,
`tol`, `create-state` and `tos-pq-consensus-key` in a dedicated build directory.
Use the pinned Cargo lockfiles and set `FUNC_PATH`, `FIFT_PATH`, `TOL_PATH` and
`TOS_ROOT` to this checkout and its compilers. For genesis sandboxes, also set
`CREATE_STATE_PATH` and make the root `build` point to the dedicated build;
otherwise the sandbox may locate a different checkout's toolchain.

The validation boundaries and retained receipts are indexed in
[`protocol-v16-validation.json`](protocol-v16-validation.json). The evidence
covers actual VM acceptance/rejection, cross-language parity, real generated
zerostates, contract execution, provider policy and both mobile clients.

The sensitivity runner intentionally sets each changed gate to 15 and 17,
requires its intended assertion to fail, restores the original headers and
requires both suites to pass again:

```sh
python test/protocol-v16/mutations.py --build "$TOS_BUILD_DIR" \
  --scenarios "$PQ_ARTIFACTS/scenarios.tsv" \
  --rust-results "$PQ_ARTIFACTS/rust.tsv" --out "$PQ_ARTIFACTS/mutations"
```

Use `test/pq-falcon512/prepare.py`, `compile_probes.py` and `exotic.py` to
produce those scenarios, execute both parity drivers, and check them with
`compare.py`. Keep assertion-enabled Python. The runner rejects compiler or
driver errors as mutation evidence.
