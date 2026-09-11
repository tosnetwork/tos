# D64 statement construction: partial delivery

Specification: memo `8f02a558`, SHA-256
`38e340e2afe6fa8e468125855fcd1261cd3bc0d0cd4ae69a716c9e8888a7e29d`.
This supersedes the relation-choice stop in `workchain-m5-host-gap-inventory.md`;
it does not close that inventory's host, state, routing or funding-retirement gaps.

## Implemented boundary

D66 follow-up (specification `c7da55fddeee326e`): added
`withdrawal_public_bound_is_not_a_constructor_gate` before removing the
redundant public bound check. The test first exited 101 at its named D66
assertion, then passed after the check was removed. The full prover library
run (`cargo test --manifest-path uno/prover/Cargo.toml --locked --offline
--release --lib`) passed 12 tests. This control establishes the constructor
boundary, not a new proof of range-proof soundness.

B's committed `uno/crypto/src/tests.rs` changes were inspected: shared witness
slots, equal handles and canonically decoded wrong points exercise the same
direct relation ABI purpose. The ABI inventory first exited 1 with
`crypto.abi.boundary_changed`; after independently hashing the file, only its
identity was updated, and the guard exited 0. Neither its purpose nor the
scanner rules changed. This identity acceptance is not an external audit.

The Rust-only `WithdrawalStatement` reconstructs a SEND-shaped statement from
P_A, old C/D, new C/D and J. It accepts no P_B, C_t, D_tA or D_tB parameters.
Principal, outward fee and return reserve are added with checked arithmetic;
the positive total is formed before scalar conversion. Under D66, T <= V_max
is enforced by the existing range proof, not a second constructor gate.
Operation fee remains the separate f.
The opening transcript uses `uno-v2/withdrawal-opening`, with explicit domain,
Withdrawal ID, Attempt ID, owner P and total; zero reduced scalars are rejected.
P_B=P_A and both handles use the same derived r. The original relation file
and its eight equations/six witnesses/six range objects are unchanged.

The statement context has an explicit Withdrawal prefix, both IDs and all four
amount fields followed by the supplied authenticated host context. This is a
Rust construction interface, **not a completed Native wire/context codec**.
The host must independently reconstruct/authenticate the latter before use.
Opening r is public transient wallet data, not a stored state or wire field.

## Executed evidence

Commands (CARGO_TARGET_DIR set to
`/tmp/uno-merge-6ea2fbf80-tL5Uih/m3-vector-wallet-target`):

```sh
cargo test --manifest-path uno/prover/Cargo.toml --locked --offline --release --lib
cargo test --manifest-path uno/crypto/Cargo.toml --locked --offline --release --lib withdrawal_statement
python3 crypto/test/workchain-crypto-abi-boundary.py --repo .
```

- Prover regression: 11 passed, 0 failed, including three new Withdrawal tests
  and all existing frozen SEND/COLLECT and system-COLLECT cases.
- Zero-opening control: 1 passed. It injects a zero wide scalar into the exact
  reduction/rejection helper, not a claim to have found a zero transcript hash.
- ABI inventory: 25 files, unchanged; no new C ABI symbol/call is connected.
- A valid ordinary SEND proof with v=T-1 and context naming T passes the raw
  relation but fails reconstructed Withdrawal verification specifically with
  UNO_CRYPTO_VERIFY. This is not an earlier shape/host-comparison rejection.
- Changing each generated point separately fails real verification with
  UNO_CRYPTO_VERIFY. Both identical handle rows remain; deleting one redundant
  row is not claimed to permit minting.
- Equal total with outward fee increased by one and reserve decreased by one
  yields identical points but a different challenge; the original proof fails
  with UNO_CRYPTO_VERIFY. This proves binding of the split, not its independent
  authentication by a host.

Red control: an isolated source copy at `/tmp/uno-d64-red-9PyQCj` changed only
the derived commitment amount from T to T-1. Running
`withdrawal_smaller_debit_raw_send_passes_specialization_rejects` exited 101:
the assertion expected Err(UNO_CRYPTO_VERIFY), observed Ok(()). It reached the
intended verification assertion, not compilation or malformed-input rejection.
The main source was never mutated; its restored-condition regression passes.
Logs: `/tmp/uno-d64-red-mutant.log`,
`/tmp/uno-m5-withdrawal-prover-regression.log`,
`/tmp/uno-m5-withdrawal-zero.log`, `/tmp/uno-m5-withdrawal-abi-guard.log`.

## Remaining integration, not claimed complete

The B-owned Native Withdrawal wire/context and Attempt/state interfaces have
been requested directly. There is no new host call before its admitted metering
entry, no node Withdrawal dispatch, and no completed no-pending host check or
its behavioral mutant yet. Thus **step 1 is only partially delivered**.
The Rust tests cannot substitute for the required node rejection.

Still pending: split-wc0 rich bounce acceptance and controls; old M3 pure/epoch
funding helper retirement plus operation/whitelist removal; D61 payout fee
direction correction (first red under the new rule); D65 W/return accounting.
The D61 independent accounting prediction was not requested or read.

D34 wording: no new relation family, but additional review surface. C_t
derivation and the no-pending branch are minting-critical; handle derivation
supplies algebraic binding with redundancy when P_B=P_A. Under the existing
proof system's soundness assumption, this public-opening algebra adds no
computational assumption.
No cryptographic reliability, production availability, M5 live acceptance or
completed test-funding retirement is claimed. No production C++ consensus file,
Native schema, refusal branch or D59 default has changed in this step.
