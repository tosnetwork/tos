# Service Actor funding and settlement

The Service Actor separates three kinds of value: customer obligations, the
operator's backing, and the execution funding attached to the current message.
Successful operations must not pay their execution costs from existing backing.
A refund's principal ranks ahead of the operator's operating buffer, while all
other customers' obligations remain protected.

## Accounting rules

All amounts below are native nanotos. Let:

- `B` be the compute-phase balance minus the incoming message value. It is the
  preexisting backing **after this transaction's storage charges**.
- `L` be pending prices, refundable prices, and locked storage fees.
- `R` be the minimum operating reserve, currently 1 TOS.
- `F` be the incoming execution funding, separate from any new escrow payment.
- `A` be the authorized payout: refund price, cleanup bounty, or withdrawn revenue.

`B` is captured once and never reduced while checking obligations. All monetary
arithmetic uses checked operations. Checks subtract obligations individually so
an aggregate that cannot fit a Coins field still receives a deliberate refusal.

| Operation | Backing required before committing | Native balance retained after success |
| --- | --- | --- |
| Admission | `B >= old L + R`; incoming value covers price, storage fee and execution allowance | `B + price + storage fee` |
| Refund | `B >= refund price + remaining customer L` | `B - refund price` |
| Sweep | `B >= bounty + remaining L + R` | `B - bounty` |
| Withdrawal | `B >= amount + L + R`; amount does not exceed booked revenue | `B - amount` |

The incoming execution budget cannot be counted as backing in any of these
checks. An insolvent account needs an explicit top-up before it can admit new
work, pay a bounty, or withdraw revenue. A zero withdrawal is allowed at the
funded floor and returns its unused execution budget.

The refund rule deliberately excludes `R`. A reserve deficit alone cannot stop
a fully backed customer refund. If storage rent has already consumed customer
backing too, the refund remains pending and the operator must replenish the
shortfall. Refusal does not extend the existing claim deadline; expired claims
remain subject to the contract's documented sweep policy.

## Action-phase enforcement

Admission reserves `B + price + storage fee` exactly, then sends only the
remaining native balance back to the caller with mode 128. That remaining value
is the incoming execution budget minus actual gas and forwarding fees. Reserving
only `L + R` would let the call spend or return the operator's excess.

Payouts use one exact reserve and two ordered sends:

1. Reserve `B - A` with mode 0.
2. If `A > 0`, send exactly `A` to the beneficiary with mode 1.
3. Send the unused execution funding to its original sender with mode 128.

A refund destination controls where principal is sent; it does not redirect the
caller's execution change. No action uses the ignore-errors flag. If either
send cannot pay its fees, all outbound messages and persistent changes roll
back. Tests exercise failure both at the principal send and at the later change
send. Network transaction fees are still charged on failed transactions.

One mode-128 transfer combining principal and change would not provide this
guarantee: an execution shortfall could be deducted from principal while the
claim was nevertheless deleted. The two-send construction preserves an exact
principal obligation even if fees rise beyond the expected execution allowance.

The supported executor uses extra-currency v2 semantics: mode 128 carries native
coins, leaving unrelated extra currencies untouched. A regression checks this
for both admission and refund. These tests do not promise pre-v10 execution
semantics.

## Client contract

The SDK publishes `ADMISSION_GAS_ALLOWANCE`, `PAYOUT_GAS_ALLOWANCE`, and the
checked `minimum_call_payment` calculation. A call below price plus storage fee
still receives 1902. Insufficient additional execution funding receives 1929.
Unbacked admission receives 1928. Refund/sweep backing shortfalls retain 1921;
withdrawals beyond the actual affordable revenue retain 1922.

The CLI derives omitted call funding from the quoted policy and the SDK
allowance. Payout defaults and preflight checks derive from the payout allowance.
The deployment default remains 1.2 TOS, derived from the 1 TOS operating reserve
and a named 0.2 TOS deployment margin. A top-up uses an empty internal message;
attached payout execution funding is returned after costs rather than silently
being donated to repair the operator's account.

The E2E observer checks the principal and change separately. Its fee calculation
uses gas and full forwarding fees from the raw transaction; the forwarding total
already contains its action-fee component. Recipient execution fees do not
change the principal value recorded in the Service Actor's outgoing message.

## Reproducible evidence

Use the repository's pinned Rust toolchain and compiler binaries built from this
checkout. Set `FUNC_PATH` and `FIFT_PATH` when using binaries outside `build/crypto`.
`TOS_ROOT` is optional for local runs inside the checkout; discovery prioritizes
the enclosing worktree over a different checkout at `~/tos`.

```sh
export CARGO_INCREMENTAL=0
python3 scripts/check-service-actor-bytecode.py --write
cargo test --manifest-path tosctl/src/Cargo.toml --locked -p contracts --test service_actor_sandbox -- --nocapture
cargo test --manifest-path tosctl/src/Cargo.toml --locked -p contracts --lib service_actor
cargo test --manifest-path tosctl/src/Cargo.toml --locked -p contracts --test previous_release_sandbox service
cargo test --manifest-path tosctl/src/Cargo.toml --locked -p commands --lib --no-default-features solvency_tests
cargo test --manifest-path tosctl/src/Cargo.toml --locked -p tos_sandbox --lib paths::tests
python3 scripts/service-actor-solvency-mutations.py
python3 -m unittest discover -s test/pq-native -p 'test_e13_service_*.py'
make -C tosctl/src fmt-check
```

The sandbox suite is the authoritative CI source/artifact equality gate.
`--write` explicitly regenerates the SDK BOC; without that flag the utility only
checks it. Mutations compile alternate source and require the intended behavioral
assertion to fail, rather than accepting a compile failure as evidence.

The gas stress fixture constructs 99,999 real pending/refund entries and 99,001
caller keys, including a caller with 999 live entries. It measures existing and
new caller admission, both sweep branches, refund, and withdrawal. Sparse
near-uint64-limit request IDs and wide historical Coins fields stress traversal
and encoding; actual storage rent is measured separately. The assertion requires
at least 25% execution-budget headroom for this profile.

This fixture raises only the account-state cell limits to materialize the
contract's declared capacity. Normal chain limits can reject smaller unique-cell
states; this is an execution-cost stress measurement, not a claim of production
capacity. Fee settings remain unchanged. Exact reserves and exact principal sends
remain the safety boundary when a different chain configuration exceeds the
measured allowance.

Changing the compiled code changes its hash and calculated deployment addresses.
Existing deployments are not upgraded by updating the source or the SDK.

## Recorded execution profile

The measurements below use the checked-in Genesis global version (16), the
masterchain fee profile, Rust 1.97.1, and native compilers built from the checkout.
The native compiler and emulator sources are unchanged from
`e4fdd7c0e33a17f93fb64941643fad76ecaa393c`.

- FunC source SHA-256:
  `3595d8f2a74a1f5cea5f833a58828d896d5857c529616a48b55d71db64a5c1ae`
- Compiled code root hash, equal to the SDK's embedded BOC:
  `8ec36e9fa8e9507b5f35b57b59680888e23394dc1f5a48a5d25b51e11ecacfed`

| Stress operation | Gas used | Gas charge (nanotos) | Full forwarding charge (nanotos) | Total execution charge (nanotos) |
| --- | ---: | ---: | ---: | ---: |
| Admit new caller | 74,058 | 37,029,000 | 500,000 | 37,529,000 |
| Admit existing caller | 73,724 | 36,862,000 | 500,000 | 37,362,000 |
| Refund | 68,778 | 34,389,000 | 1,000,000 | 35,389,000 |
| Sweep pending | 76,906 | 38,453,000 | 1,000,000 | 39,453,000 |
| Sweep refundable | 76,079 | 38,039,500 | 1,000,000 | 39,039,500 |
| Withdraw | 16,073 | 8,036,500 | 1,000,000 | 9,036,500 |

All six operations succeeded with compute exit 0 and action result 0. The
largest execution charge consumes 19.7265% of the 200,000,000-nanotos allowance.
The fixture contains 495,340 unique cells and raises the account cell cap to
496,364 solely for this measurement. Actual storage charges were
13,399,357,735,767 nanotos just before the claim deadline and
13,399,362,905,274 nanotos at it; preexisting backing paid this rent separately.
The gas-bound tests print these values with `--nocapture` so they can be
remeasured when fees, compiler output, or the network version changes.

### Native transaction replay

`SERVICE_ACTOR_TRACE_DIR` records the exact configuration, inbound message,
pre-state, time/logical time, raw Rust transaction, and after-state. Recording
requires exactly one Service Actor transaction per cascade, so a later callback
cannot silently change the meaning of the captured after-state. Use a fresh
trace directory for each run and stop on a failed test before replaying:

```sh
set -eu
cmake --build build --target emulator -j2
service_actor_trace_dir=$(mktemp -d)
for service_actor_case in \
  solvency_claim_preserves_other_entries_and_reserves_after_fees \
  solvency_refund_never_haircuts_principal_when_fees_rise \
  solvency_exact_withdrawal_cap_cannot_spend_fee_backing \
  solvency_zero_withdrawal_at_floor_returns_execution_change \
  solvency_payouts_require_execution_budget
do
  SERVICE_ACTOR_TRACE_DIR="$service_actor_trace_dir" \
    cargo test --manifest-path tosctl/src/Cargo.toml --locked -p contracts \
      --test service_actor_sandbox "$service_actor_case" -- --exact
  test -s "$service_actor_trace_dir/$service_actor_case/0000.json"
done
python3 scripts/replay-token-bridge-trace.py "$service_actor_trace_dir" \
  --emulator build/emulator/libemulator.so
```

These five cases produced 32 transactions with zero native differences,
including principal-send failure, later change-send failure, and a funded retry.
The comparison covers compute gas/status, action result, bounce, native TOS
output messages and balances, and code/data hashes. It does not establish
extra-currency parity, all storage metadata, recipient execution, or the live
wallet/RPC/finality path.

The raw-receipt sensitivity control copied one admission record and replaced
only `shard_account_after` with its `shard_account`. Native execution succeeded,
but replay exited 1 and reported the intended balance mismatch
(19,999,653,500 versus 20,299,653,500 nanotos) and a data-hash mismatch. The
unmodified recordings replayed successfully. Existing normalized `expect`
recordings also replayed 32 transactions with zero differences.

## Validation index

Local Linux results for the source and code hashes above, recorded 2026-10-21:

| Boundary | Result | Exit status |
| --- | --- | ---: |
| Complete Service Actor sandbox suite | 58 passed, 0 failed, 0 ignored | 0 |
| SDK Service Actor unit tests | 12 passed | 0 |
| Previous-release Service Actor refusal | 1 passed | 0 |
| CLI funding/default/preflight tests | 5 passed | 0 |
| Shared source-root resolver | 3 passed | 0 |
| Source/artifact equality with `TOS_ROOT` unset | 1 passed | 0 |
| Service DTO, sandbox-backed indexer lifecycle and HTTP state | 7 passed | 0 |
| Python transaction-evidence controls | 36 passed | 0 |
| Contract mutation runner | 14 baseline tests passed; all 14 broken rules detected | 0 |
| Native replay | 32 transactions, 0 differences | 0 |
| Native expected-state sensitivity | Wrong raw after-state rejected for balance and data differences | 1, expected |
| Cargo workspace format, Python lint/format, actionlint, whitespace | Passed | 0 |

The contract runner records the intended assertion for each rejected mutant.
For example, restoring the old admission settlement leaves 1,486,904,500 nanotos
where the invariant requires 1,500,000,000. Removing the admission reserve leaves
zero. Restoring the operator buffer in the refund floor triggers 1921 in a case
that must refund successfully. Replacing exact principal and change with one
carry-all send incorrectly succeeds under the elevated-fee test. Removing each
of the three payout execution-budget guards is tested independently.

Additional local controls removed the CLI's admission allowance or bypassed
its early funding validation, preferred `~/tos` over the enclosing worktree,
omitted E2E fee subtraction, and ignored compiler path overrides. Each made its
specific assertion fail; restored tests passed. These controls can be reproduced
by applying each change separately and running the corresponding CLI, resolver,
or Python suite above. Local results used disabled incremental compilation
after an incremental-cache compiler failure; no production source was changed
for that workaround.

The downstream consumer selection matters: `cargo test -p service --lib
service_actor` selects only the DTO test. Run the `indexer_` cases and
`get_service_request_returns_authoritative_pending_state` as well to execute the
embedded contract's admission, response, refund and sweep paths.

Relevant CI boundaries are `contract-sandboxes (suites)` (contract, artifact,
mutation, source discovery and Python evidence), `rust-workspace-tests-compile`
(CLI and all Rust test targets), `service` (downstream consumers), `rust-format`,
`hygiene`, and `source-guards`. The required `strict-build`,
`native-registry-reproducibility`, and `python-and-pq-chain` checks also remain
merge gates. The local result table is not a statement that these checks have
completed on a subsequently published commit. Live Service Actor CLI, wallet,
RPC and finality rehearsal was not run locally.
