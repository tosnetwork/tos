# Slice 3 Release Notes

Status: Slice 3 release package complete on 2026-04-30. The maintainer
accepted the repo-side Stage 8 surrogate as the release gate.

## Supported Patterns

Slice 3 supports these stdlib packages and scaffolds:

| Pattern | Import | Scaffold | Notes |
| --- | --- | --- | --- |
| Ownable | `@stdlib/ownable` | helper only | Owner checks and two-step transfer helper. |
| Jetton | `@stdlib/jetton` | `tol new --pattern jetton` | Wire-compatible helpers for master/wallet builders and error mapping. |
| NFT | `@stdlib/nft` | `tol new --pattern nft` | TEP-62 collection/item builders, royalty replies, static-data replies. |
| Wallet v5 | `@stdlib/wallet` | `tol new --pattern wallet` | Raw signed internal/external body shape is preserved. |
| Multisig | `@stdlib/multisig` | `tol new --pattern multisig` | Signer, duplicate signer, threshold, proposal replay, expiry, and action validation helpers. |

## Budget Snapshot

The current green gates are:

| Gate | Result |
| --- | --- |
| Full tol-tester | 629/629 tests passing, gas 5248281 |
| Emulator fixtures | 26 test(s) passed |
| Slice 3 replay runner | 2 Slice3Replay emulator tests passed |
| Slice 1 Tol gas | Jetton minter 17122, Jetton wallet 33791, wallet-v5 39313 |
| FunC-vs-Tol parity | Jetton minter 0.810, Jetton wallet 0.483, wallet-v5 1.311 <= wallet threshold 1.35 |

Stage 3 and Stage 5 preserved the checked reference Tol BoC hashes for
Jetton and wallet-v5 after stdlib wrapper migration. PR #6 later
recaptured the Jetton minter Tol baseline after adding the explicit
`addr_none` admin rejection, and recaptured wallet-v5 after making
signed-internal seqno advancement survive action-phase failure; these
are reference-contract safety changes, not TL-B constructor, TVM opcode,
or wire-format changes.

## Escape Hatches

- Use raw builders where a TEP wire shape requires `any_address`,
  external addresses, or hand-packed wallet-v5 bodies.
- Use `@unknown_throw(...)`, `@unknown_silent_drop`, or
  `receive(msg: UnknownOpcode)` to make unknown-opcode policy visible.
- Use `@disclaim_query_id` only when a receiver intentionally does not
  reply with the inbound `queryId`, or when a raw legacy send propagates
  it in a way the compiler cannot prove and the exception is documented.
- Use explicit `require(cond, ErrorClass.X, code)` when an ABI requires
  a pinned error code.
- Use `@method_id(N)` when an existing get-method ABI is already fixed.

## Unsupported In Slice 3

Slice 3 does not implement supervision, scheduled messages, capability
handles, bounded postponement, trait/behaviour syntax, protocol
timeouts, or any new wire surface. Wallet-v5 external messages remain
outside the internal Envelope/query-id preflight model.

## Release Verification

Run:

```sh
cmake --build build --target tol test-emulator -j 32
cd tol-tester && FIFTPATH=../crypto/fift/lib FIFT_EXECUTABLE=../build/crypto/fift TOL_EXECUTABLE=../build/tol/tol python3 tol-tester.py tests
python3 scripts/check-slice-1-gas.py
python3 scripts/check-slice-3-replay-fixtures.py
python3 scripts/check-slice-3-scaffold.py
python3 scripts/check-slice-3-release-package.py
git diff --check
```
