# Elector review follow-up

This follow-up addresses the two source findings against
`5df2222c1049e165560637a85a3dd1ae5aa32bbf`. It changes the existing single-query,
single-flight protocol. It does not deploy contracts or migrate a live chain.
The original `elector-security-results.json` describes the earlier revision;
its hashes and totals are historical, not validation of this follow-up.

## Subsequent R3/R4 candidate: not ready for deployment

The follow-up below is historical. The new candidate on top of
`9615ff13a0e1859c917af796f3a77f6a4315e73e` preserves a nonempty recovery
confirmation book across upgrades and checks the target's runtime schema
capability. Remote commits `764a10c15` and `1377e4863` supersede the local
R4 implementation: they additionally check that compatibility probing does not
mutate data and that a supplied upgrade hook preserves recovery history. A
compatible installation need not supply a hook; an incompatible target must
still refuse without one. Native tests cover lost-confirmation repair,
incompatible targets, and repeated ACKs without another principal payment.
The same-code test constructs a drained upgrade precondition; it does not
prove a live-chain drain or migration.

The controller change protects explicitly accepted plain funding and authenticated
legacy receipts. **R3 remains open:** an aborted non-bounce message can retain
unrelated value without updating the protected-capital record. The READY
balance sweep then pays that value to the current pool. A separately executed
native counterexample fails the intended ownership assertion (exit 101).
Passing the four candidate tests does not close this defect.

See `elector-r3-r4-results.json` for source hashes, scoped checks, mutation
results and the remaining failure. Release/golden artifacts and deployment
remain on hold. These changes are review candidates, not complete remediation.

## Recovery confirmation outlives a staking result

The pool's paid-recovery reference now contains its own query, pinned elector
and gross amount. Replacing the latest staking result preserves that reference.
The pool only clears it after the pinned elector confirms the same recovery
query with opcode `0x47656133`. A successfully enqueued ACK is not completion.

The elector sends this confirmation after clearing the outstanding receipt,
and also when the same ACK is repeated against the already-cleared tombstone.
The existing outstanding guard and replay tombstone remain. New recovery is
blocked while the pool still needs confirmation; its normal recovery command
first repairs that confirmation, and a later call can recover new credit.
Public pool operation `8` also repairs it during another staking round. Both
public repair paths require the caller to fund their control message and gas.

This adds an explicit **recovery ACK confirmation**, distinct from controller
relay cleanup. Relay still uses one ACK and no ACKED message, one query and one
pending slot. There is no unbounded receipt list, second relay counter, bond or
new revenue allocation. Only an authenticated confirmation, rather than a later
business result, can retire the pool's pending recovery repair record.

The native cross-round test runs both accepted and rejected next stakes. It
omits the first recovery ACK, processes the later staking result, rejects forged
source/query confirmations, uses the public repair operation, loses the first
confirmation too, retries it, then serves/unfreezes another real election and
recovers the new principal. Replayed old receipts do not distribute principal
or rewards again; the final elector outstanding count is zero.

## Controller-authoritative sequence allocation

The controller accepts exactly `sequence + 1`, starting at `(1 << 63) + 1`.
Both acceptance and the `next_relay_query` getter check exhaustion without
wrapping or resetting. Maximum, near-maximum and nonconsecutive large queries
cannot advance metadata. Root and consensus-key changes preserve the sequence.

The election runner and Python live-chain callers read `next_relay_query` from
the controller. They no longer generate stake IDs from a wall clock. A racing
request can still be refused; it must be reconciled and reread, not blindly
retried with a timestamp. Root-owned low-domain requests are unchanged.

A single pool now retains one previous result while its new request is pending.
A real controller bounce restores that result, allowing the authoritative ID to
be reused when the controller never allocated it. It also preserves any old
paid-result ACK repair. Successful settlement drops the backup; its depth is
bounded to one previous result, not a growing history. This is local rollback
state, not a second request ID. Multi-pool forwarding already retains its last
completed result separately from the pending attempt.

## CI corrections

- The native classic upgrade/rollback controls require the pinned historical
  elector source. Contract sandbox CI now checks out full history; the checks
  are not skipped or replaced with a synthetic empty account.
- The actual failed source guard was `tosctl-pq-stake-builder-source`: it still
  matched the old two-argument receipt reader. It now requires feedback from
  the owner pool with the explicit expected controller. The Config validator
  parity guard remains enabled and unchanged.
- The lifecycle source guard now requires the authoritative query getter in
  place of timestamp allocation, while retaining builder/report query binding.
- Rust and Python formatting corrections address the failed hygiene gates.
- Two recorded answers change with the elector code: its upgrade proposal and
  the masterchain zerostate. Recompiling the old elector reproduces both old
  answers; substituting only the new generated elector reproduces the new ones.
  Config proposal/upgrade, complaint envelope, base workchain and addresses are
  unchanged. The complete recorded-answer inventory is then checked again.

## Reproduction and review limits

Run in the existing checkout with no concurrent source writer. The mutation
runner temporarily changes production FunC and restores exact original bytes;
do not run it concurrently with builds or other tests.

```sh
export TOS_ROOT="$PWD"
export CARGO_TARGET_DIR="$PWD/.git/elector-security-audit-artifacts/cargo-target"
cmake --build build --target gen_fif -j64
cargo test --manifest-path tosctl/src/Cargo.toml -p contracts -p elections --locked --no-fail-fast -j64
python3 test/pq-native/elector-review-mutations.py --out .git/elector-security-audit-artifacts/review/reproduction --jobs 64
ctest --test-dir build -L source-guard --output-on-failure -j8
scripts/check-nominator-pool-code-lock.sh
scripts/check-single-nominator-code-lock.sh
```

Results and source/artifact hashes are in `elector-review-results.json`. Raw
output stays under `.git/elector-security-audit-artifacts/review`, retained for
at least 90 days after integration. Raw access or reproduction is necessary to
independently verify the hashes. Earlier fixture/compiler failures are retained
there and are not counted as guard-sensitivity successes.

Fresh compatible controllers and pools are still required. The recovery
reference and single-pool rollback layout differ from the original PR. Do not
hot-swap these bytes into existing funded accounts. No live chain deployment,
old-state migration or production acceptance is claimed. Local validation and
GitHub checks are reported separately.
