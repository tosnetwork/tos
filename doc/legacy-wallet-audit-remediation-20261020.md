# Legacy wallet audit remediation — 2026-10-20

The four retained P0/P1 findings below are fixed on the development branch.
Historical source for the red controls is
`b56d8dc55cfe5a3203ac8fd22d6689384a768c39`. No old-state migration, old
constructor format, or old payout behavior is supported by these changes.
The audit's original fixed-source inventory remains historical evidence;
these results describe the changed source and native transactions below.

| Finding | Changed boundary | Native regression |
| --- | --- | --- |
| H-MS-01, P0 | `crypto/smartcont/multisig-code.fc`: an owner-signed, quota-independent maintenance query removes at most eight expired records; ordinary cleanup uses the same bound. A maintenance query with nothing reclaimable is refused before acceptance, so it costs the wallet nothing and keeps its ID. | Four owners each fill all ten proposal slots, let all 40 proposals expire, reclaim them over five calls without quorum, refuse maintenance replay, then complete a quorum query. |
| M-PC-PAYOUT-01, P1 | `payment-channel-code.fc`: both principals are exact amounts with send mode 1, and what remains after them goes to A (skipped only when too small to carry a message); any action failure rolls back both outputs and closing-state changes. A completing close or timeout whose balance cannot cover both principals is refused before acceptance. Payout-path amount movement is checked. Terminal payout refuses further payout commands. | With only 3 or 5 TOS backing two 4-TOS principals the close is refused before acceptance (41) with the channel balance untouched; with the principals plus 0.001 TOS it is accepted and the action phase aborts (37) with no recipient credit or state change. Funding and retry pays each principal exactly on the wire and the remainder to A; a completed payout cannot pay again after another top-up. |
| M-RW2-01, P1 | `new-restricted-wallet2.fif`: signed 32-bit elapsed-second keys, including the pre-start sentinel, agree with the receiver ABI. | Run the actual constructor, load its emitted StateInit BOC, preserve its code/key/dictionary, and supply only a fixture start time. Verify before/at each 92/183/366/548-day boundary and an actual locked transfer failure followed by success after release. |
| M-HL2-01, P1 | `highload-wallet-v2-code.fc`: each accepted query deletes at most 32 expired replay records. | Drain 4,096 expired records through 128 native transactions, checking the exact dictionary size each time. Duplicate fresh IDs and forgotten expired IDs remain refused. |

## Protocol and operational behavior

Multisig maintenance is the existing signed envelope with no co-signature
list and a body of `wallet_id:uint32 global_id:int32 query_id:uint64
0x4d534743:uint32`, with no references. An existing strong owner signs the
root envelope normally. The ID must be fresh and unseen. Maintenance is
refused before acceptance unless the oldest pending record is already
reclaimable, so an empty maintenance costs nothing and keeps its ID usable;
an accepted maintenance deletes at least one record, cannot emit messages,
consumes no proposal quota, and records its ID as processed. Only records older than
`now - 64 seconds` are removed. Use fresh IDs for subsequent batches. The
existing C++ transfer-only QueryBuilder does not build this envelope; the
native regression shows its complete serialization and signing procedure.

A payment-channel close needs funds for **both** principals plus transaction
and forwarding fees. A close or timeout that would pay out while the balance, after the
message import and storage charges, is below the two principals is refused
before acceptance, so it is not accepted
into a block and cannot be replayed against the unchanged state; only the fee
margin can still fail in the action phase, in which case fund the channel and
repeat the original close/timeout. After both exact principals, the remainder
goes to A, as before the exact payouts. Completed payout is terminal; funds
sent to a channel after its payout stay there, since nothing can spend from a
paid-out channel. The recorded amounts are historical receipts, not
outstanding claims.

Highload maintenance uses an ordinary owner-signed query with an empty
transfer dictionary. Every call still records a fresh ID. Future-dated IDs
are not pruned early; admission rate and expiration horizon still need
operational bounds. Bounded expired-record cleanup does not eliminate
unbounded retained future-query growth.

The internal-message bridge multisig variants are separate contracts; this
remediation and the quoted P0 evidence apply to `crypto/smartcont/multisig-code.fc`.
P2 findings and other conditional audit risks are outside these four changes.

## Reproduction and measured results

Run from the repository root with the repository-built native toolchain:

```sh
export TOS_ROOT="$PWD"
export FUNC_PATH="$PWD/build/crypto/func"
export FIFT_PATH="$PWD/build/crypto/fift"
cargo test --manifest-path tosctl/src/Cargo.toml --locked -p contracts \
  --test legacy_wallet_key_sandbox --test legacy_wallet_liveness_sandbox \
  --test multisig_code_sandbox --test payment_channel_sandbox --no-fail-fast
python3 scripts/test-legacy-wallet-audit-controls.py
```

Measured locally on macOS/ARM using the current Genesis global version
(16) for the new transaction regressions:

- Four test targets: **28 passed, 0 failed** (including four current-version
  fixture checks and the existing twelve-family key controls).
- Five sensitivity controls: fixed-source exit **0** in each; historical-source
  exit **101** at the intended native assertion in each. The runner uses temporary
  source copies and leaves the checkout untouched. The controls cover multisig
  quota recovery, atomic settlement, terminal repayment, the constructor ABI,
  and highload out-of-gas.
- Three changed FunC contracts compile to Fift and C++ embedding text through
  the same commands and target names as CMake `GenFif`; the constructor regression
  assembles the restricted wallet from source and executes its actual BOC.
- Rust formatting, whitespace, removed-escrow guard and classical-stake-caller
  guard pass. Existing weak-key and external-credit regressions remain green.
- Full C++ compilation/ctest is **not run locally**. The differential static
  analyzer exits **2 (REFUSED)** because the required LLVM 21 executable is
  absent; no analysis result is claimed. Linux CI must establish its own
  native/generated-code build and sandbox results for the pushed revision.

This is execution evidence from the Rust TOS VM/transaction executor and
native FunC/Fift-generated BOCs. It is not a C++ executor run, deployment,
upgrade, mainnet transaction, or production-funds acceptance.

## Small durable evidence index

`doc/evidence/legacy-wallet-audit-20261020.json` records source hashes,
regenerated embedding/code-cell hashes, test results and the bounded control
receipt. Build outputs and full logs are reproducible and are not committed.
The CI sandbox-suites job executes the five sensitivity controls after the
complete contract suite.
