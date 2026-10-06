# Local PQ network: election authorization and runtime snapshot repair

Date: 2026-10-06. PR: #143. Branch: `fix/local-pq-elections-privacy-snapshot`.

Status: **runtime implementation present; focused regressions verified;
seven-node deployment and the separate product/lifecycle callers are not signed off**.
Keep the PR draft until the remaining acceptance evidence is attached.

This document supersedes the proposal in `a0dccbb40429094f6d140af42c2aa4a77f7dce41`.
That revision retains the original seven review findings and reported incident
trace. The original investigation was pinned to `fc1492c312051a934e006af35dafc7caf7b37c47`
(base `9960de239fda55dd9888cd23893bd694af130e44`). It was a source review, not a
new live-network reproduction. Do not promote its reported observations to test
results of the current implementation.

## Scope and the follow-up review decision

The persistent development network must continue elections. A short-lived
rehearsal's lifetime spending cutoff or automatic end-of-campaign shutdown is
not its default. The follow-up review correctly separated that liveness need
from duplicate-payment prevention. #145's setup-time funding and retention work
is retained; there is no second competing funding implementation.

The repair uses shared funding helpers, a small per-candidate intent file and a
single in-flight faucet journal. It does not introduce a generic payment service,
production online root custody, a new consensus protocol, a campaign database,
or a mandatory lifetime spending limit. An unresolved or refused transaction
still raises a visible failure; continuing elections is not permission to spend
again without knowing what happened.

The scope is the disposable local `--rotate` profile. Automatic signing checks
its provisioned zero-state root, global ID, election schedule and controller
birth/code/authority identity. The deterministic development root seeds must
never authorize real funds.

## 1. Election operations

### Cause and corrected authorization

A newly deployed controller has zero operating allowance and expiry. Ordinary
capital transfers cannot authorize `ctl::relay_stake`. Its root-signed kind-4
transition is:

```text
funds_after     = funds_before + deposit
allowance_after = requested_allowance
policy_after    = requested limit, floor, payer and expiry
root_nonce_after = root_nonce_before + 1
```

`local_pq_funding.py` is shared by `local-pq-fund-controllers.py` (setup/manual
check) and `local-pq-elections.py` (steady state). It reads the real account-state
BOC and current Config20/24, builds the exact kind-4 payload and invokes the
installed `tos-pq-controller`. No contract guard is relaxed.

Default policy in `local_pq_funding_policy.py`:

- Compute the automatic grant from the current masterchain fees and the
  `stake-relay.fc` formula. Target 30 days at one request every 600 seconds:
  `ceil(30 * 86400 / 600) * grant`, for both funds and allowance.
- Renew at/below the 25% runway/expiry threshold, on policy mismatch, or when
  less than two grants remain. Deposit only `max(0, target - existing_funds)`;
  a surplus is retained and a zero-deposit renewal is valid.
- Retain the 20 TOS per-request cap, 10 TOS storage floor and a separate 20 TOS
  capital margin. Reject unsupported fees/caps instead of increasing them silently.
- Keep the root authorization's 600-second validity distinct from the 30-day
  sponsorship expiry. Amounts remain integer nano-TOS with coin-width bounds.

After sending, verify destination compute/action success, the updated root
nonce and the exact additive state transition. A wallet seqno alone is not
acceptance. Wait for account-state readback to reach the confirmed transaction;
a different hash at the same LT is rejected. Recheck ordinary balance against
recorded funds plus floor independently of the allowance.

`--check` is read-only. The persistent driver renews selected controllers before
new orders. `operations-<node>.json` and `status.json` provide readiness, runway,
heartbeat and activation observations to `check-local-pq-elections.py` and
`testnet-ctl.sh check`. They are observations, not proofs of long-term liveness.

### Restart and refusal handling

`local_pq_transactions.py` persists the exact signed WalletV1 BOC and wallet
seqno **before broadcast**, using owner-private atomic/fsynced files. Recovery
can resend that same signed request at the same seqno; it cannot invent a new
payment after an ambiguous timeout. The faucet lock excludes competing writers.
Completed records are bound to the local network, wallet and operation label.

A wallet transaction must emit the intended amount, destination, body, StateInit
and bounce flags. Its outgoing message is correlated to the actual destination
transaction using decoded TL-B BOCs and the complete bounded history window.
Wrong compute/action results and mismatched transaction identities cannot be
promoted to successful receipts.

`local-pq-elections.py` persists each candidate's query, stake body, history
baselines and capital deficit before sending capital or an order. A partial
round resumes completed candidates without paying or authorizing them again.
An older sent intent is reconciled before starting a newer round; an unsent
expired intent is superseded rather than broadcast.

`local_pq_election_evidence.py` requires a successful pool receipt for acceptance.
It recognizes a native bounce by the real bounced flag, both addresses, query
and retained 256-bit request prefix. An exit code comes only from the matching
controller transaction; otherwise it remains unknown. Exit 180 is a shared
relay guard code, not a unique missing-authorization diagnosis. Refusals are
persisted, reported and not silently paid again on the next process restart.

## 2. Privacy generator and snapshot admission

There were two runtime checkout dependencies: the pool gas-ceiling source and
`groth16-development.json`, reached when preparing the first transfer/withdrawal.
`runtime_resources.rs` embeds both with `include_str!`; the generator uses that
module for fees and development-key matching. The source-consuming deployment
utility and VM compiler remain deliberately separate.

The generator's `resources` operation returns an explicit versioned response.
`check-local-pq-resources.py` verifies `ok: true`, an object result, exact source
and fixture bytes, the 1,248-byte verifying key and both contract gas ceilings.
Exit zero, `init`, malformed/non-object JSON and stale resources are not success.

`install-root-services.sh` keeps the existing symlink, ELF loader/RPATH and
Python `.pth` checks. Before publishing `current`, it also runs the staged
binary via systemd with `ProtectHome=true`, both source/build roots inaccessible,
a clean environment and resource/time bounds. Failed admission leaves the old
published snapshot in place. The privileged CLI continues to require root.
A literal source-path string scan is not treated as proof of runtime dependency
or independence.

The installer unit tests use a test-only wrapper around the real `check()`
function because their systemd transport is simulated. Separate tests require
the production CLI to reject non-root callers before admission. No test bypass
or environment switch is added to the production installer.

## 3. Verification record

### Retained CI evidence for `366595825f112da95f7ed924b47d03d51bdebd47`

Run `37417613277`, generator job `112119614121`, passed:

- compilation of the real resource-reader mutation controls;
- release build/tests of `local_pool_traffic`;
- generation of two deposits, a private transfer and a withdrawal with the
  original checkout unavailable;
- actual protected systemd admission, plus rejection of a protocol-valid
  generator that deliberately reads the hidden checkout.

The same revision's native `strict-build` job `112119613775` passed in run
`37417613269`. These results belong to that revision, not automatically to a
later commit. Its focused Python CI had six unprivileged installer-fixture
failures, and hygiene reported formatting/import issues; they were not green.

### Continuation repair and independent checks

The six installer-fixture failures were reproduced as an ordinary user and
fixed without weakening production root admission. The focused/local Python
suite now passes **215 tests and 9 subtests**, including the existing
absence-drill tests. This run used Python 3.13.5 and available offline dependencies;
it is not a substitute for the repository-locked Python 3.14 CI run.

The new regressions reject non-object resource responses, non-root CLI calls,
wrong StateInit/bounce flags in wallet outputs and a mismatched transaction hash
at the confirmed LT. The deposit/allowance field-swap mutation is killed by the
real Python wire oracle (assertion failure, not a collection failure).

All 21 PR-touched Python files pass repository-pinned Ruff 0.15.2 lint and format
checks. A temporary retained formatter was consumed for this offline repair;
the final workflow does not download unused wheels or retain that helper binary.

The retained `3665958` native generator was independently replayed in a fresh
container where `/home/runner/work/tos/tos` did not exist. The embedded resources
matched; two deposits, a transfer and a withdrawal generated successfully, with
liabilities and nullifier-count transitions checked. This is real proof/message
generation from that CI binary, **not** a new native rebuild, VM execution or
live-chain transaction acceptance.

### Remaining acceptance gates

1. Attach the final commit's locked Python/hygiene and native CI conclusions.
2. On an explicitly disposable network, retain two actual Config34 rotations,
   participant/accepted amounts, common full block IDs across all seven nodes,
   relay checks, restart evidence and renewed operating state. Do not reset a
   healthy retained network merely to obtain this evidence.
3. Under the installed privacy service's protection, confirm actual on-chain
   deposit, private transfer and withdrawal, including the cross-node checks.
4. The independent `nominator-pool-lifecycle-e2e.py` and
   `pq-config-wallet-first-stake-e2e.py` are **not repaired or certified by the
   local-driver tests**. They still need explicit controller authorization
   provisioning and preservation/selection of the original deployment transaction
   before the product script's current single-history-entry assumption can be
   removed. Do not present their product `config-wallet`/`daemon` paths, a full
   unfreeze/withdrawal lifecycle, or production costs as covered by this repair.

The continuation did not install services, merge this PR, restart validators or
erase `/data`. Source checks and generated messages do not establish a deployed
network's health. Keep those claim boundaries visible in the PR summary.
