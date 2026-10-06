# Local PQ network: two defects found on a clean redeploy (2026-10-06)

Status: **proposal for review**. This document describes two defects, how they
were found, how to reproduce them, and the fixes proposed. No fix is
implemented yet; the implementation follows after the proposal is reviewed.

Both defects were found by redeploying the local network from `main` at
`9960de239` with:

```bash
sudo scripts/setup-testnet.sh --build --clean --rotate
```

followed by the documented bootstraps of `tos-pq-transfers` and
`tos-pq-privacy`. The chain, the four genesis validators, both observers, the
lite-client and `tos-pq-transfers` work. Validator rotation (`tos-pq-elections`)
and private traffic (`tos-pq-privacy`) do not.

---

## Defect 1: the election driver never authorizes controller operations

### Cause

`af26748c6` ("Fix R3 relay debt accounting and recover bounced return
deliveries", 2026-10-02, merged to `main` through PR #135) made a validator
controller forward a stake only within an explicit, root-signed operating
authorization (controller action kind 4, `fund_operations`). In
`crypto/smartcont/validator-controller-v1.fc`, `ctl::relay_stake` now requires:

```func
int grant = sr::automatic_value();
throw_unless(sr::error, (now() < expires) & (grant <= limit) & (grant <= permission) & (grant <= funds));
int capital = sr::sub(pair_first(get_balance()), msg_value);
throw_unless(sr::error, capital >= sr::add(funds, floor));
```

A newly deployed controller has no operating record, so `ctl::operations()`
returns `(0, 0, 0, 0, 0, my_address())`. With `expires = 0`, `now() < expires`
is false and every relay throws `sr::error` (180).

`scripts/local-pq-elections.py` deploys each candidate's controller and pool
and then submits stakes. It never sends a kind 4 authorization. The manual
procedure is documented in `doc/Local-PQ-Network.md` ("Controller funding
before election rehearsal", `d2599c691`), and the documented workaround is a
start hold on the election service. However, `setup-testnet.sh --rotate` still
enables `tos-pq-elections` immediately, so a clean `--rotate` deployment
always reaches the failure below unless the operator remembers the hold and
the manual funding.

A second, smaller problem makes the failure hard to read. The driver's
`accepted()` predicate only looks for an Elector reply on the pool. A
controller refusal arrives at the pool as a native bounce, which the predicate
does not recognize. The driver therefore reports a confirmation timeout
instead of a refusal.

### Symptom

- `tos-pq-elections` logs `election_submitting`. Sixty seconds later it logs
  `failed: TimeoutError: election transaction confirmation timed out` and
  exits with status 1.
- `Restart=on-failure` restarts it after 30 seconds. It re-reads the open
  election and submits again, and fails again. Each attempt sends another
  11,020 TOS of faucet capital to the candidate pool before the stake order.
- No stake is accepted, so no election completes. The chain keeps producing
  blocks on the genesis set after that set's `utime_until`; rotation simply
  never happens.

Observed on-chain path for node 1 (pool `-1:1a7c65…`, controller
`-1:15e26d…`), one attempt:

| Step | Transaction | Result |
| --- | --- | --- |
| Faucet → pool | 11,020 TOS | credited |
| Wallet → pool, stake order | 20 TOS | pool forwards 11,005.64 TOS to the controller, op `0x50517232` (relay), query `0x8000000000000001` |
| Pool → controller | relay | compute `exit_code 180`, `gas_used 122995` (ML-DSA signature check passed), `aborted`, bounce |
| Controller → pool | bounce, 11,004.40 TOS | principal returned; no Elector message was sent |

Getter output on the live chain at the time:

```
runmethod -1:15e26d…  operating_state  ->  [ 0 0 0 0 0 CS{…own address…} ]
runmethod -1:553af8…  operating_state  ->  [ 0 0 0 0 0 CS{…own address…} ]
```

### Reproduce

1. `sudo scripts/setup-testnet.sh --build --clean --rotate` on `main`.
2. Wait for the first election to open (about 5 minutes after Genesis):
   `sudo journalctl -u tos-pq-elections -f`.
3. Observe `election_submitting` followed 60 s later by the timeout failure.
4. Confirm the cause with the lite-client:

   ```bash
   L="sudo /usr/local/bin/tos-lite-client -C /data/configs/node-1-lite.json -v 0 -c"
   C=$(sudo jq -r .controller /data/elections/candidate-1.json)
   $L "runmethod $C operating_state"        # all zero, expiry 0
   $L "getaccount $C"                       # note last transaction lt/hash
   $L "lasttransdump $C <lt> <hash> 1"      # compute_ph exit_code:180, aborted:1, bounce
   ```

### Proposed fix

1. **Authorize operations in the driver.** In `local-pq-elections.py`, after a
   candidate's controller is deployed and before any stake is submitted:
   - Read `controller_state` (authority epoch, root nonce) and
     `operating_state` (funds, allowance, per-request limit, floor, expiry,
     payer).
   - If the authorization is missing, expires within two election periods, or
     funds or allowance fall below two per-request limits, build the kind 4
     payload: payer address, deposit, allowance, per-request limit, storage
     floor as coins, and expiry as `uint32`. Sign it with
     `tos-pq-controller fund-operations` using
     `/data/elections/keys/root-<i>.seed`, the chain's global ID, the current
     epoch and nonce, and an authorization expiry of `now + 600`.
   - Send the signed body from the faucet wallet. That wallet is the bound
     payer, and the service already owns it exclusively. The message carries
     the deposit plus the documented processing fee.
   - Wait until the root nonce increments and `operating_state` reads back the
     requested values. Emit an `operations_funded` event. If the nonce does
     not move, or the readback differs, fail with a clear message. Never
     resend blindly.
   - Top up ordinary controller capital so that
     `balance ≥ funds + floor + margin`. As the existing doc notes, an
     ordinary transfer is capital only, not authorization.

   Initial values are the development example already recorded in
   `doc/Local-PQ-Network.md`: deposit 80 TOS, allowance 60 TOS, per-request
   limit 20 TOS, floor 10 TOS, one-day sponsorship, plus a 20 TOS capital
   top-up. These are development values, not production fee estimates. They
   are re-checked before every round, so a long-running rehearsal replenishes
   instead of running out.

2. **Encode the payload in Python, pinned to the real encoder.** Add a small
   encoder next to `build_pool_stake_order` in
   `test/tostester/src/tostester/pq_election_fixture.py`. Its unit test
   compares the BOC byte for byte against the output of the Rust encoder
   (`contracts::validator_controller::operating_funding_payload`, example
   `controller_operating_payload`), captured once from the real binary, not
   computed by hand.

3. **Ship the signer.** Add `tos-pq-controller` to the `setup-testnet.sh`
   build targets and install it as `/usr/local/bin/tos-pq-controller`. The
   election service runs from the root-owned snapshot with `ProtectHome=true`,
   so it cannot use the copy in the checkout's `build/`. The driver resolves
   it through the same executable-admission check it uses for the lite-client.

4. **Recognize a controller refusal.** Extend `accepted()` to detect a native
   bounce from the candidate's controller for the submitted query. Fail
   immediately with the decoded exit code and the returned amount, instead of
   waiting for the 60 s timeout. A refusal is not retried automatically.

5. **Remove the workaround from the docs.** Replace the "current scripts do
   not initialize…" warning and the hold instructions in
   `doc/Local-PQ-Network.md` with a description of what the driver now does
   and how to read `operating_state`. Keep the diagnosis table.

6. **Audit the other live-chain stake scripts.**
   `scripts/pq-config-wallet-first-stake-e2e.py` and
   `scripts/nominator-pool-lifecycle-e2e.py` also relay stakes through a
   controller. Both were last changed on 2026-10-02. Check whether they
   authorize operations; fix them the same way if not, or record that they
   are out of date.

### Verification plan

- Unit tests: payload encoding against the Rust golden output; the funding
  decision for missing, expiring and depleted authorizations; the refusal
  detection on a recorded controller bounce.
- Negative control: with funding disabled, the driver must report a controller
  refusal with exit 180 within seconds, not a timeout.
- Live: a fresh `setup-testnet.sh --clean --rotate` must show:
  - `operations_funded` for nodes 1, 2, 3, 4 and 7;
  - four `stake_accepted` per round;
  - Config34 switching from {1,2,3,4} to {1,2,3,7} and back over two rounds;
  - a common full block ID on all seven nodes;
  - a passing `scripts/check-local-pq-relays.py`.

---

## Defect 2: the private traffic generator reads the checkout at runtime

### Cause

`local_pool_traffic` (`b2c500dc6`, 2026-09-29) computes each operation's fee
from the pool contract's declared gas ceiling. It calls
`contract_gas_ceiling()` in
`tools/shielded-pool-circuit/crosscheck/src/pool.rs`, which reads the contract
source at runtime:

```rust
pub fn library_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../crypto/smartcont/shielded")
}
let path = library_dir().join("../tos-shielded-pool-v1.fc");
let source = std::fs::read_to_string(&path)?;
```

`env!("CARGO_MANIFEST_DIR")` is fixed at compile time, so the binary contains
the absolute checkout path, for example
`<checkout>/tools/shielded-pool-circuit/crosscheck/../tos-shielded-pool-v1.fc`.

`5147c8f46` (2026-10-04) moved `tos-pq-privacy` to a root-owned snapshot under
`/usr/local/lib/tos-dev-services/` and runs it with `ProtectHome=true`. The
snapshot copies only the generator binary, not the contract source. Even if it
did, the baked path still points into the checkout under `/home`, which the
unit hides.

The snapshot checker (`scripts/install-root-services-check.py`) verifies ELF
`RPATH`/`RUNPATH` entries and `.pth` files. It does not look for checkout paths
compiled into a binary as data, so it accepted this snapshot.

### Symptom

- `local-pq-privacy.py --bootstrap` succeeds. It runs from the checkout under
  `sudo`, outside the unit, so `/home` is visible to it.
- `tos-pq-privacy` starts and fails on its first operation:

  ```
  ValueError: generator refused: fixture:
  <checkout>/tools/shielded-pool-circuit/crosscheck/../../../crypto/smartcont/shielded/../tos-shielded-pool-v1.fc:
  No such file or directory (os error 2)
  ```

  `/data/privacy-transfers/status.json` records `kind: failed`. The unit has
  `Restart=no`, so it stays down.

### Reproduce

```bash
B=/usr/local/lib/tos-dev-services/current/src/tools/shielded-pool-circuit/crosscheck/target/release/local_pool_traffic
sudo grep -a -o -E "$HOME/tos/tools/shielded-pool-circuit/crosscheck[^[:cntrl:]]{0,40}" "$B" | sort -u
# shows the baked checkout path
sudo systemd-run --wait --pipe -p ProtectHome=true \
  test -r "$HOME/tos/crypto/smartcont/tos-shielded-pool-v1.fc"; echo $?
# 1: the file is invisible to the unit
```

End to end: bootstrap as documented, then
`sudo systemctl start tos-pq-privacy` and wait for the first operation (20–60
seconds).

### Proposed fix

1. **Embed the contract source at compile time.** In `pool.rs`, read the source
   with `include_str!` instead of `read_to_string`:

   ```rust
   const POOL_SOURCE: &str = include_str!(concat!(
       env!("CARGO_MANIFEST_DIR"), "/../../../crypto/smartcont/tos-shielded-pool-v1.fc"));
   pub fn contract_gas_ceiling(name: &str) -> Result<i64> { gas_ceiling_in(POOL_SOURCE, name) }
   ```

   The ceiling is still parsed from the contract, not copied into a constant,
   so the property the existing comment protects is unchanged. Cargo tracks
   `include_str!` inputs, so a mutation of the `.fc` rebuilds the tests that
   read it. `pool_sources()`, which the in-process `Pool` compiler uses, is a
   test-only path. It is not reached by `local_pool_traffic` and stays as it
   is.

2. **Make the snapshot checker catch this class of bug.** Add a check to
   `install-root-services-check.py` that refuses a snapshot when any regular
   file contains the source checkout's absolute path as a byte string. Add a
   positive control: a fixture file containing the checkout path must be
   refused, and the same file without it must pass.

3. **Run the generator the way the unit runs it.** Add an installer
   self-check that executes the snapshot's `local_pool_traffic` once under
   `systemd-run -p ProtectHome=true` with a fee query. This catches any
   remaining runtime dependency on the checkout before the service starts.

### Verification plan

- Unit test: `contract_gas_ceiling` returns the same values as before for every
  name the generator uses.
- The snapshot checker's positive and negative controls as above. Also confirm
  that the current, unfixed binary is refused by the new check.
- Live: reinstall the snapshot. Bootstrap and run `tos-pq-privacy` until it
  has confirmed at least one deposit, one private transfer and one withdrawal,
  with the per-operation cross-node checks it already performs.

---

## Why CI did not catch these

- No CI job boots a chain and runs an election through the local driver. The
  driver's unit tests (`scripts/test_local_pq_elections.py`) do not execute a
  controller. The contract sandboxes do fund operations
  (`elector_security_audit/relay/r3_accounting.rs`), so the contract is
  covered; its only real-chain caller is not.
- The root-services tests check the snapshot's dynamic-linking and Python
  search paths. They never run the generator under the unit's
  `ProtectHome=true`.

Both fixes include a check that would have failed at the introducing commit.

## Current state of the local network

- Running: DHT, validators 1–4 and 7, observers 5 and 6, lite-client and
  `tos-pq-transfers`.
- `tos-pq-elections` is stopped and disabled until defect 1 is fixed, to stop
  the retry loop from spending faucet capital.
- `tos-pq-privacy` is disabled until defect 2 is fixed.
- The start hold `/var/lib/tos-local-maintenance/elector-redeploy.hold` was
  renamed to `elector-redeploy.hold.retired-20261006` so the traffic services
  could start. That hold was the documented guard for defect 1. With the
  election service disabled, it is no longer needed. The fix for defect 1
  removes the need for it entirely.
