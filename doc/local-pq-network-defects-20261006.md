# Local PQ network: election authorization and runtime snapshot defects

Date: 2026-10-06.

Status: **reviewed and corrected implementation proposal; runtime fixes are not implemented in this PR yet**.

Review baseline: `tosnetwork/tos@fc1492c312051a934e006af35dafc7caf7b37c47`,
branch `fix/local-pq-elections-privacy-snapshot`, PR #143. Its parent/base is
`9960de239fda55dd9888cd23893bd694af130e44`; the original PR changed only this
document. Keep the PR draft until the implementation and required evidence below
are present. Approval of this plan is not approval of an untested implementation.

The two reported root-cause directions are supported by the inspected code.
However, the original fix was incomplete: in particular, it missed a second
runtime fixture read, specified an unsafe replenishment/readback model, and did
not close the restart/repeated-funding path.

## 1. Review decisions and evidence boundary

### Required corrections to the original proposal

Priorities below are implementation/release blockers for this local-development
workflow, not claims of an exploitable production consensus vulnerability.

| ID | Priority | Finding | Required correction |
| --- | --- | --- | --- |
| R1 | P1 | `fund_operations` adds the deposit to existing funds but replaces the allowance and other policy fields. Repeating an 80 TOS deposit is not replenishing to 80 TOS. | Use a bounded deficit deposit; distinguish renewal from funding; confirm previous funds plus deposit, not deposit alone. |
| R2 | P1 | The driver sends 11,020 TOS before each attempt and writes `submitted.json` only after the whole roster. A crash, partial round, or ambiguous timeout can repeat funding and already accepted work. | Persist per-action/per-candidate intent before broadcast, reconcile bounded transaction histories, and make deterministic failures non-retrying. |
| R3 | P1 | `development_vk_bytes()` also opens a checkout file and is reached by the first transfer/withdrawal. Embedding only the contract source fixes deposits, not private traffic. | Embed both required resources and check that the generator, deployment and embedded inputs belong to the same build. |
| R4 | P1 | The generator has no fee-query operation. `init` reads neither resource. Request failures produce `{"ok":false,...}` while the process can still exit zero. | Add an explicit resource self-check and validate its output; exercise actual deposit/transfer/withdrawal paths in an isolated acceptance test. |
| R5 | P2 | A checkout byte string anywhere in a regular file is not proof of a runtime dependency; debug/diagnostic/source metadata can contain it. Absence is not proof of independence either. | Keep structural security checks, use string scanning as a diagnostic inventory, and make isolated execution of the staged artifact the runtime admission test. |
| R6 | P2 | A native bounce does not contain the controller's compute exit code. Matching only sender/query also permits stale or insufficiently correlated observations. | Decode the real bounced flag and full retained request prefix; obtain any exit code from the correlated controller transaction. |
| R7 | P1 | Updating shared fixture setup can break the product first-stake script's explicit `len(history.transactions) == 1` deployment assumption. | Preserve/select the original deployment transaction before new funding transactions; make both live caller regressions mandatory. |

### Decisions on the original questions

1. **Automatic checking before every round: yes, for the explicit disposable
   local-development profile only. Automatic unconditional deposits: no.**
   Initialize/check all five candidates and re-check selected candidates before
   sending stakes. Renew or replenish only when required and within persisted,
   operator-approved campaign limits. Do not turn this into production online
   custody of validator root keys.
2. **80/60/20/10 TOS and one day are bounded development policy examples**, not
   protocol constants or measured universal fees. Treat 80 TOS as an operating
   funds target, 60 TOS as the allowance target, 20 TOS as the per-request cap,
   and 10 TOS as the storage floor. Ordinary capital is topped up by the actual
   deficit, not by blindly adding 20 TOS. Validate actual current-price budgets
   before accepting these values; halt rather than silently increasing caps.
3. **Embed every immutable checkout resource reachable by the installed traffic
   generator**, including the development verifying-key fixture. Keep deliberate
   source-consuming build/compiler utilities separate. `pool_sources()` is not
   strictly test-only: `src/bin/local_pool.rs` calls it during deployment
   generation. It need not be made runtime-independent as part of this repair,
   but it must not become reachable from the installed traffic service.

### What was and was not independently checked

The review inspected the driver, controller and relay contract code, fixture
message/receipt helpers, controller signer, setup/snapshot scripts, privacy
library and both generator entry points, the product first-stake setup path,
and the existing operational guide at the pinned revision. It also ran 12 small
Python semantic probes covering additive/deficit funding, integer nano-TOS
boundaries, capital deficit calculation, native-bounce prefix correlation,
non-I/O code containing a checkout filename, and JSON failure with process
success. Those are counterexample/policy probes, **not repository regression
coverage or executions of the Rust generator**.

No seven-node network, systemd installation, Rust/C++ build, controller VM test,
or live-chain reproduction was run by this review. The original operator's
observations below are retained as reported evidence, not relabeled as a new
independent run. Introducing-commit attributions and current host service state
remain the reporter's account unless separately verified against history/host
telemetry. The other lifecycle caller still requires complete implementation
and execution review; the product deployment-history conflict is already visible.

## 2. Defect 1: the election driver never authorizes controller operations

### 2.1 Cause supported by the current code

In [validator-controller-v1.fc](../crypto/smartcont/validator-controller-v1.fc),
`ctl::operations()` defaults to `(0, 0, 0, 0, 0, my_address())`.
`ctl::relay_stake` requires:

```func
int grant = sr::automatic_value();
throw_unless(sr::error, (now() < expires) & (grant <= limit) & (grant <= permission) & (grant <= funds));
int capital = sr::sub(pair_first(get_balance()), msg_value);
throw_unless(sr::error, capital >= sr::add(funds, floor));
```

The [local election driver](../scripts/local-pq-elections.py) deploys candidate
controllers and pools, then sends stakes, but never submits root action kind 4.
Consequently the zero authorization cannot pass these guards. An ordinary
transfer changes balance, not the authorization record. The manual procedure in
[Local-PQ-Network.md](Local-PQ-Network.md) already explains this distinction.
The reporter attributes the integration gap to `af26748c6` / PR #135.

The driver's `accepted()` only recognizes business receipts through
`elector_reply()`. The helper does not classify a pool's native bounce from a
controller. A refusal can therefore become a generic confirmation timeout.

**Exit 180 is a shared relay guard code, not a unique missing-authorization
code.** Zero operating state establishes a missing prerequisite; an exit code
or gas figure alone does not prove which guard failed in a particular trace,
or that every earlier check passed. Do not disable controller guards, skip PQ
verification, or change consensus/elector rules to repair this caller defect.

### 2.2 Original operator's reported symptoms

Reported command, on base `9960de239`:

```bash
sudo scripts/setup-testnet.sh --build --clean --rotate
```

**Destructive local-development reproduction: `--clean` deletes `/data`.** Do
not run this against a retained network or real funds. Pin the revision when
reproducing; a moving `main` is not a reproducible baseline.

The reporter observed `election_submitting`, a timeout after 60 seconds, then a
30-second `Restart=on-failure` loop. Each attempt added another 11,020 TOS to a
candidate pool. The original set continued producing blocks without the intended
rotation. The precise expired-set/Config34 behavior requires its own retained
chain evidence; successful authorization alone is not proof of consensus liveness.

One reported node-1 path, with abbreviated addresses:

| Step | Value/body | Reported result |
| --- | --- | --- |
| Faucet to pool `-1:1a7c65…` | 11,020 TOS | credited |
| Wallet to pool stake order | 20 TOS | pool sends relay `0x50517232`, query `0x8000000000000001`, value 11,005.64 TOS |
| Pool to controller `-1:15e26d…` | relay | compute exit 180, gas used 122995, aborted |
| Controller to pool | native bounce, 11,004.40 TOS | principal returned net of costs; no reported Elector acceptance |

The reporter also captured zero `operating_state` records. Implementation
acceptance must retain full addresses, transaction LT/hash, raw transaction
BOCs, block identities and getter responses; abbreviated figures are diagnostic
context, not a substitute for that evidence.

### 2.3 Exact authorization and funding semantics

The contract's kind-4 transition is:

```text
funds_after       = funds_before + deposit
allowance_after   = requested_allowance
limit_after       = requested_limit
floor_after       = requested_floor
expires_after     = requested_sponsorship_expiry
payer_after       = requested_payer
root_nonce_after  = root_nonce_before + 1
```

The sender must equal the signed payer. The incoming message must cover:

```text
deposit + gas_fee(-1, sr::relay_gas) + sr::control_value()
```

A zero deposit is usable for a policy/expiry renewal but still requires the
processing value and a valid root signature. The wallet transaction's success
or seqno increment is not proof of controller compute/action success.

The current [stake-relay.fc](../crypto/smartcont/stake-relay.fc) defines:

```text
control_value = gas_fee(-1, 50000) + forward_fee(-1, 4096, 8)
callback_value = gas_fee(-1, 200000) + forward_fee(-1, 4096, 8)
automatic_value = 4 * control_value + callback_value
funding_processing_minimum = gas_fee(-1, 200000) + control_value
```

Implement current masterchain fee calculation with the same rounding and
configuration semantics, tested against the VM helpers. Do not infer a grant
from `gas_used`, treat a reserved grant as actual gas spent, or hard-code the
manual 100 TOS funding message as a universally sufficient fee. A changed fee
configuration that exceeds approved policy must fail explicitly.

### 2.4 Bounded replenishment algorithm

All amounts and calculations are integer nano-TOS, with checked coin range
`0 <= value < 2^120`. Epoch/nonce are uint64 and expiries uint32; reject
out-of-range values before invoking the signer. Do not send fractional top-ups
through a float conversion to TOS.

1. Verify the development profile, live zero-state identity, global ID,
   candidate/controller/pool/code bindings, current root public key and bound
   consensus identity. Securely read `controller_state`, `operating_state`,
   balance and pending relay/retry state. Validate full getter success and stack
   shape, not the first integer printed by `lite_int()`.
2. First reconcile any outstanding journal entry. As an orchestration policy,
   do not change sponsorship while a relay/return-retry is unresolved. Either
   complete observation/recovery or stop with evidence; do not overwrite payer
   or budget underneath an in-flight request. Unexpected root/payer/policy
   changes require operator reconciliation, not automatic takeover.
3. Check whether the authorization covers the next round and its confirmation
   margin, with an expiry renewal horizon of at least two election periods.
   Replenish when recorded funds or allowance are below the chosen reserve
   threshold; retain the proposed two-per-request-limit threshold only when
   the targets can support it. Require `automatic_value <= limit`, funds and
   allowance and validate the renewal horizon against live Config15.
4. If healthy, send no authorization transaction. If renewal/replenishment is
   required, use `deposit = max(0, funds_target - funds_before)` and replace the
   allowance with its approved target. An expiry-only renewal at/above the
   funds target has deposit zero. Never auto-withdraw surplus or increase an
   operator's caps to force progress.
5. Use chain time from a recent verified observation for the validity decision;
   distinguish the root authorization TTL (for example 600 seconds, at most
   the contract's 3600) from sponsorship expiry (for example one day). Re-read
   before signing if observations are stale. Check both uint32 ranges.
6. Persist the exact intent and signed/broadcastable message before submission,
   including pre-state and caps. Sign with the installed, admitted
   `tos-pq-controller fund-operations`; its output is a body, not a transaction
   submission. Submit from the exact bound wallet with separately budgeted
   processing and delivery margin.
7. Confirm the correlated controller transaction's compute/action outcome and
   intended body, unchanged epoch, exact next root nonce, and the full expected
   operating tuple. In the quiescent state this means `old_funds + deposit`,
   not simply the deposit. An unexpected nonce change does not prove our
   particular action was applied. Any intervening state change must be
   reconciled from transactions, never hidden by weakening equality checks.
8. Re-read actual balance after funding/fees. Calculate ordinary capital
   separately, verify its delivery, then check the pre-relay balance condition
   again immediately before staking. A changed fee/balance observation must not
   cause an unbounded top-up loop.

Deficit arithmetic, **not a complete transaction implementation**:

```python
NANO = 10**9
funds_target = 80 * NANO
allowance_target = 60 * NANO
per_request_limit = 20 * NANO
storage_floor = 10 * NANO

# Only after validation, quiescence, journal reconciliation and policy approval.
deposit = max(0, funds_target - old_funds)
expected_funds = old_funds + deposit
expected_allowance = allowance_target

# Use a fresh, confirmed post-funding balance here, not the old balance.
# capital_margin is explicit bounded development policy, not a protocol fee.
capital_topup = max(
    0, expected_funds + storage_floor + capital_margin - post_funding_balance
)
```

For example, 70 TOS of recorded funds needs a 10 TOS deposit to reach 80;
repeating 80 would record 150. With funds 80, floor 10, a chosen capital margin
20 and post-funding balance 88, the capital deficit is 22 TOS, not a fixed 20.
Post-transfer costs still require readback of the actual invariant.

Persist per-message, per-controller and per-campaign spend/renewal limits.
Unresolved sends consume the outstanding budget until reconciled. Successful
rounds do not provide an unlimited faucet or recover old stake automatically:
this driver must remain a bounded rehearsal unless a separate, tested principal
recovery policy is implemented. Cap exhaustion is a visible stop condition.

### 2.5 Restart safety is part of the fix, not optional follow-up

The existing round-level `submitted.json` is insufficient. Introduce durable
per-candidate/per-operation records scoped by **zero-state identity, election,
controller and pool**. Funding additionally binds authority epoch/nonce; staking
binds query, commitment and the exact outbound message.

Before any call that can broadcast, persist intent, amount, before-state,
wallet seqno, signed message/body hash, validity window, transaction-history
baselines and the chosen roster. Use private, ownership-checked files and
crash-durable replacement (file fsync, atomic rename, parent directory fsync).
A journal created only after `wallet.send()` cannot close the crash window.
If exact retransmission is supported, the wallet adapter must separate message
preparation from submission and retain the exact serialized external message.

On start/restart:

- Acquire exclusive ownership of the driver and faucet write path. Preserve the
  existing requirement to stop elections during traffic bootstrap; make sure a
  concurrent manual instance or restart cannot race its seqno. A code comment
  claiming exclusive ownership is not a locking mechanism.
- Reconcile from retained transaction LT/hash anchors with pagination and a
  bounded complete observation window. The latest history page alone is not
  proof of absence. Incomplete history, conflicting identity, stale reads or a
  timeout mean **unresolved**, not failed/not sent.
- Resume observation of an included operation; never add fresh principal or a
  new kind-4 deposit simply because an RPC or process timed out. Only an
  explicitly permitted, identical, still-valid wallet envelope may be
  retransmitted after checking its deduplication boundary. A new wallet seqno
  carrying another transfer is not that retransmission.
- Record each accepted/refused candidate before advancing. Never resubmit an
  already accepted candidate because another member failed. Pool capital
  funding is the verified available-capital deficit, not another unconditional
  11,020 TOS; reconcile returned/pending principal before calculating it.
- Persist a deterministic controller refusal or policy violation as a halted
  action. Map it to a dedicated non-restarting exit status (for example 78 with
  `RestartPreventExitStatus=78`) and check the persisted halt even after a
  manual service restart. Transient read failures may retry only through the
  same reconciliation path. Fix the misleading setup comment that a restart
  loses nothing.

Distinguish `prepared`, `submitted`, `observed`, `confirmed`, `refused` and
`unresolved` states. Root funding nonce, wallet seqno and relay query are three
different counters and are not interchangeable idempotency keys. Do not advance
rotation merely because a skipped/partial election was appended to a file:
persist the roster and advance the completed rotation after verified Config34
activation, with explicit treatment of election closure.

### 2.6 Correct refusal detection and diagnostics

For a pool receiving a native controller bounce, decode the actual transaction
BOC/message header and require all of:

```text
internal message; bounced == true
source == candidate controller; destination == candidate pool
body marker == 0xffffffff
retained 256-bit prefix == relay_op:uint32 | query:uint64 | commitment:uint160
transaction belongs to the recorded attempt's complete history window
```

This matches the shape guarded by `sr::bounce_matches`; truncated or differently
bound data is not a matching refusal. Correlate the preceding pool-to-controller
message as well. Reused queries after rejected attempts make history/commitment
binding especially important. An ordinary message whose body starts with
`0xffffffff` is not sufficient.

The bounce contains the original request prefix, **not the compute exit code**.
Fetch/decode the corresponding controller transaction for compute exit code,
abort flag and action result, and distinguish compute failure from action-phase
failure. If unavailable, report `controller_bounced` with unknown exit code and
keep the evidence incomplete; never synthesize 180. Report the returned amount
from the actual bounce value, not from the original principal.

Also observe wallet-to-pool refusal and successful receipt application. A missing
bounce or missing recent-page receipt must not be converted into acceptance.
Keep Elector business refusal (including closed-election reason 0) separate from
controller refusal and observation failure.

### 2.7 Encoding, signer custody and other callers

Add the pure funding-payload encoder beside `build_pool_stake_order` in
[pq_election_fixture.py](../test/tostester/src/tostester/pq_election_fixture.py).
Pin field order and bounds to
`contracts::validator_controller::operating_funding_payload` and the actual
`controller_operating_payload` example. Test decoded field equality and cell
hash; byte-for-byte BOC comparison requires the same explicit serialization
flags. Use a Rust-generated golden and an executable cross-language test, not
only a golden maintained by the same Python encoder. Cover zero deposit,
workchain/payer encoding, coin bounds, TTL bounds and trailing fields.

In `setup-testnet.sh`, add the real target `tos-pq-controller`, check the output
`build/crypto/tos-pq-controller` before destructive setup, and install it as
`/usr/local/bin/tos-pq-controller`. Admit the executable and its actual loaded
dependencies, not just its ownership; test it in the protected service context.
Do not fall back to a PATH entry or checkout binary. Validate signer exit status,
base64/BOC shape and body fields before funding.

The root signing tool is deliberately separate from the validator node. Its use
by this root-run local service is a **development-fixture exception**, guarded
by the disposable-network profile and matching genesis/candidate artifacts.
Never put a production root seed on a validator host to implement this feature,
weaken seed ownership/mode checks, log seeds, or replace root authorization with
the consensus key. Read keys only from the secured fixture location and verify
the public root against current controller state before signing.

Both `scripts/nominator-pool-lifecycle-e2e.py` and
`scripts/pq-config-wallet-first-stake-e2e.py` are mandatory companion work, not
"fix or declare outdated" alternatives. Reuse the same bounded initialization
and verify every controller that their support/target stakes use. Preserve the
product caller as the actual stake sender rather than bypassing it with fixture
submission.

In the product script, `product_run()` calls lifecycle setup and then requires
exactly one controller transaction to obtain the birth StateInit. Moving funding
into a shared setup method can invalidate that assertion before the product
stake starts. Either capture/validate the original deployment transaction before
authorization, or paginate and select the unique original deployment by account,
StateInit/code/data identity and status. Never replace it with "take the newest
transaction" or derive the birth witness from mutated live data. Exercise both
`config-wallet` and `daemon` modes after this change.

Keep the operational hold/manual safety instructions until the implemented
preflight and failure behavior have passed validation. Then replace only the
missing-authorization workaround; preserve independent maintenance/start holds,
bootstrap mutual exclusion and operator-controlled stop mechanisms.

## 3. Defect 2: the private generator has two checkout dependencies

### 3.1 Complete reachable cause

In [crosscheck/src/pool.rs](../tools/shielded-pool-circuit/crosscheck/src/pool.rs):

- `contract_gas_ceiling()` reads
  `library_dir().join("../tos-shielded-pool-v1.fc")`, where `library_dir()` is
  based on compile-time `CARGO_MANIFEST_DIR`. The service reaches this through
  `fee("deposit_gas_ceiling")` and `fee("transact_gas_ceiling")`.
- `development_vk_bytes()` independently reads
  `CARGO_MANIFEST_DIR/../fixtures/groth16-development.json`. In
  [local_pool_traffic.rs](../tools/shielded-pool-circuit/crosscheck/src/bin/local_pool_traffic.rs),
  the first transfer/withdrawal initializes proving keys and compares the
  generated canonical verifying key against this file. It is not a test-only
  helper in this call graph.

The reporter attributes the source read to `b2c500dc6` and the protected snapshot
transition to `5147c8f46`. `install-root-services.sh` copies the traffic binary,
not either of these resource files, and the service uses `ProtectHome=true`.
For a checkout hidden by that setting the original absolute runtime reads fail.
The reported first failure names `tos-shielded-pool-v1.fc`. Once that is fixed,
the second read remains a deterministic source-level blocker for the first
proof-generating operation in the same environment.

The reported successful bootstrap does not validate either path. `plan("init")`
returns before both resource reads. Likewise, `main()` encodes request errors
as `ok:false` and continues, ultimately returning `Ok(())` on input EOF. Process
exit status alone cannot certify a generated operation.

### 3.2 Embed both resources without changing contract semantics

Use compile-time resources shared by the existing parsing/validation functions:

```rust
const POOL_SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../crypto/smartcont/tos-shielded-pool-v1.fc"
));
const DEVELOPMENT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../fixtures/groth16-development.json"
));
```

`contract_gas_ceiling()` must parse `POOL_SOURCE`; `development_vk_bytes()` must
parse `DEVELOPMENT_FIXTURE`. Retain the generated-verifying-key equality check.
Do not copy fee numbers into unrelated constants, skip key comparison, supply an
empty/default key on failure, or make the service open `/home` again. Parsing
must reject missing/malformed data, invalid hex and invalid gas values rather
than silently truncating or substituting defaults.

These are compile-time dependencies: a resource change must rebuild the relevant
artifact before a test compares it to newly compiled contract code. Add a
mutation/rebuild test so changing the contract ceiling or verifying-key fixture
cannot leave a passing stale binary. Tests deliberately compiling sources via
`Pool`/`pool_sources()` may keep their explicit build-tree dependencies;
`src/bin/local_pool.rs` is a build/deployment utility, not the installed service.
Audit the remaining service call graph for filesystem reads instead of assuming
all other helpers are test-only.

Because setup permits use of existing binaries without `--build`, add public
resource/build metadata to the generator self-check and deployment evidence:
embedded contract-source digest, embedded fixture/canonical VK digest, gas
ceilings, and the relevant build identity. Compare these against the trusted
setup inputs and the pool deployment/code/data identity. Refuse a stale or
mismatched artifact with a rebuild instruction; do not publish a snapshot whose
fees/key describe a different pool. Keep this an artifact/deployment check, not
a new on-chain version or weakened contract identity check.

### 3.3 Snapshot policy: structural checks plus real execution

Retain every existing ownership, symlink traversal, `.pth`, RPATH/RUNPATH,
loader-token and dynamic-dependency check in
[install-root-services-check.py](../scripts/install-root-services-check.py).

Replace the proposed "reject any regular file containing checkout bytes" rule
with a diagnostic inventory of suspicious references. A filename in diagnostic
metadata or Python code objects need not cause any file access. Conversely,
constructed paths or a different build checkout can evade a scan for today's
source path. Debug stripping/remapping can reduce noise but is not a runtime
independence proof. Do not introduce blanket exceptions that bypass the existing
loader or `.pth` security gates.

The decisive runtime check for the exercised paths must run the **new staged
`DEST`**, before changing `BASE/current` and before deleting previous snapshots.
It must not accidentally test the old `current` symlink or bootstrap from the
checkout. A failed/unsupported admission test must leave the old published
snapshot intact and the failed candidate unpublished; no silent live-install skip.

Use a transient service with the real protected environment, working directory,
resource bounds and `ProtectHome=true`. Explicitly hide the canonical source and
build roots as well when they are outside home, for example via validated
`InaccessiblePaths=` settings. Ensure those roots do not overlap the staged
snapshot or required runtime directories. Pass properties/arguments without shell
interpolation vulnerabilities and verify the isolation with a negative control.
Do not rename, chmod or delete the real source tree as a test mechanism.

### 3.4 Two-layer self-check with explicit success criteria

**Fast install admission.** Add a defined `local_pool_traffic --self-check`
command which reads both embedded resources through the production helpers,
validates the two gas ceilings and canonical development VK data, and returns
only public metadata/digests. It must not contact the chain, generate notes,
change `/data`, or print secrets. Unknown options or failure must be nonzero.
The installer must require a nonempty valid success record with all expected
fields; an old binary that ignores the option and exits zero at EOF must fail
admission. There is no existing fee-query operation to invoke.

**Full isolated artifact regression.** Drive the production JSON protocol in a
private ephemeral directory through init, two funded model deposits, a private
transfer and a withdrawal, consuming the actual returned state at every step.
Validate every response's `ok == true`, nonempty BOC, expected liability/root
transitions, generated key equality and proof/signature path. Use amounts and
inputs that actually satisfy the configured denominations and withdrawal fee.
Give proof generation bounded CPU, memory and timeout limits; exhaustion is a
failure, not a pass. Validate all operation responses, not only process status.

The full regression need not run on every ordinary service start, but is a
required pre-merge/pre-release gate in a capable environment. Unit-only/non-root
installer tests may fake the executor to test sequencing; they must be labeled
as such and must not count as the real protected execution test. Keep temporary
note secrets out of journald/public reports and remove private fixture state.

Required controls:

- The original binary with hidden sources fails the deposit path.
- A source-only embedding patch still fails at first transfer/withdrawal because
  of the VK read; the complete fix passes the same sequence.
- `init`-only, an empty output, malformed JSON, missing fields and `ok:false`
  with exit zero all fail the admission wrapper where success is required.
- A harmless embedded checkout filename is not itself classified as runtime I/O;
  an actual/constructed runtime dependency is caught by isolated execution.
- A stale resource digest is refused even if files exist in the administrator's
  checkout. Existing malicious RPATH, `.pth` and symlink fixtures remain refused.
- Snapshot self-check failure leaves `current` and previous usable snapshots
  unchanged. No generator smoke test sends a transaction on the retained chain.

## 4. Required implementation and acceptance gates

| Gate | Evidence required before claiming completion |
| --- | --- |
| Funding wire | Rust/Python decoded payload and cell hash agreement; canonical BOC golden; actual C++ signer output accepted by controller VM; wrong payer/root/nonce/epoch/network, malformed values and expired authorization refused. |
| Funding policy | Missing, healthy, low-funds, low-allowance, expiry-only/zero-deposit, excessive grant, inadequate floor/capital, conflicting payer/root, pending relay and spend-cap cases. Expected funds use the additive transition. |
| Fee compatibility | Current masterchain grant/processing calculation compared with `sr` VM helpers, including rounding and changed-fee rejection. No silent cap escalation. |
| Crash/restart | Kill before broadcast, after broadcast before observation, after wallet inclusion, after controller acceptance and after the first candidate succeeds; restart must not duplicate principal, deposits or accepted stakes. |
| Observation | Pagination beyond the first history page; truncated/stale/wrong-source/wrong-prefix bounces; ordinary messages imitating bounce bodies; compute vs action failure; missing trace stays unresolved. |
| Service behavior | Deterministic refusal halts durably and does not loop under systemd/manual restart; transient RPC failure reconciles safely; concurrent faucet writers are excluded. |
| Companion callers | Full nominator lifecycle and product first-stake `config-wallet` and `daemon` paths; correct original deployment/Birth StateInit selection after new funding transactions. |
| Resource regression | Both embedded resources validated; source/key mutation plus rebuild fails/passes as intended; stale no-build generator is refused. |
| Snapshot safety | Existing installer security tests plus staged-artifact checks, fake-success/error controls, source/build isolation and no publication on failure. |
| Actual elections | Fresh disposable setup; operating authorization verified for candidates 1/2/3/4/7; four successful stake paths per completed round; intended Config34 activation in both directions; common full block IDs on all seven nodes. |
| Actual privacy | Installed protected service confirms deposit, private transfer and withdrawal on the disposable chain with its existing per-operation cross-node checks. |
| Bounded recovery/closure | Force an authorization renewal/depletion without waiting a day, verify no repeated funding after interruption, verify campaign-cap stop, and retain exact code/build/transaction identities. |

Run/extend the existing `scripts/test_local_pq_elections.py` and
`scripts/test_install_root_services.py`, companion caller tests and the real
controller/relay sandbox tests. Add the resource regression to the real generator
suite. Ensure CI path filters include changed Python helpers, contract inputs,
fixture JSON, generator sources and install scripts; optional skip paths are not
completion evidence. The current source inspection is not a claim that every
workflow in the repository was audited.

For live election acceptance, use `scripts/testnet-ctl.sh check` and
`scripts/check-local-pq-relays.py` after both activations and the transition grace
period. Check the full common block ID, not just matching height or Config34
bytes. Receipt acceptance, election selection and validator activation are
separate milestones. A two-round rehearsal still does not prove all later
unfreeze/withdrawal paths, production-duration liveness, or production costs.

## 5. Operational state and completion language

The original reporter stated that elections were stopped/disabled to prevent
faucet depletion, privacy was disabled, and the manual
`elector-redeploy.hold` had been renamed while traffic services were restarted.
This review did not access that host and does not assert these are its current
states. Keep automation halted on an affected retained deployment until an
operator has reconciled existing principal, authorizations and pending actions.

Implementation order: add/refine failure controls and observation tests; implement
bounded initialization plus durable reconciliation; update companion callers and
signer installation; embed both privacy resources and add isolated staging tests;
then run the disposable-chain acceptance gates and update the operational guide.
Do not remove independent safety holds or merge merely because the proposal was
reviewed. Record implemented/compiled/unit-tested/VM-tested/live-tested separately.
