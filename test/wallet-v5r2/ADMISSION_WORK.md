# Experimental external admission work profile

The node accepts one explicit startup option:

```
--ext-message-work-profile CONFIG_ROOT,CAPACITY,REFILL_UNITS,INTERVAL_NS,ATTEMPT_UNITS,MAX_BYTES,MAX_DEPTH
```

`CONFIG_ROOT` is the lowercase 64-digit hash of the complete authenticated
configuration dictionary (not a block hash or ConfigParam 48 hash). The remaining
fields are canonical unsigned decimal integers. Capacity, refill, interval,
attempt charge and input bounds must be positive; a single attempt must fit the
capacity. Byte/depth bounds are uint32; work values and interval are uint64.
Duplicate options, extra fields, noncanonical integers and overflow are rejected.

There is no calibrated production default. The option is absent by default.
Choose work units, interval and burst only from measurements covering the full
attempt cost for every supported destination, including special accounts,
precompiled execution, parsing and lookup. The small numbers in unit tests are
synthetic accounting fixtures, not deployment recommendations.

A configured pool charges the shared work budget immediately before checker
dispatch, after waiting for an inflight slot. All origins use that charge. Failure,
completion and cancellation do not refund work; byte/inflight occupancy still
releases. The checker executes a rejected contract once, without a diagnostic
replay. Consensus block validation does not consult this local budget.

Stopping the pool explicitly fails all queued admission promises during actor
teardown. Waiting coroutines retain the actor, so deferring promise cleanup until
destruction would create a reference cycle and retain their input bytes. Queue
errors propagate before dispatch and consume no work tokens. Dropping an external
`StartedTask` handle detaches its work; it is not a request to cancel execution.

The exact configuration pin deliberately refuses unrecognized configurations.
It also changes on unrelated configuration updates such as validator rotations.
The internal options API can explicitly rebind a reviewed configuration without
resetting tokens or the refill clock. Capacity, rate, attempt cost and input-bound
changes require restart. Unrelated options updates cannot disable an already
installed work budget. The startup flag is not a live file watcher.

Release gates remain: supported-profile update policy, measured hardware
calibration, ordinary failed external transactions reporting zero charged gas,
queued configuration changes/cancellation, real network origin coverage, mixed
attack/recovery fairness, and the actual version-18/default-credit transaction
corpus. This option alone does not resolve V5R2 release admission.

## Reproduction and verification scope

The `External admission work boundaries` workflow builds the real engine on
Linux x86-64 and AArch64. Its checks map to these boundaries:

| Boundary | Check |
| --- | --- |
| Token accounting, refill, overflow and initial gas quote | `test-ext-message-admission-budget` |
| Pool dispatch, configuration matching, rejected VM call count, live options and queued shutdown | `test-ext-message-pool` |
| Manager broadcast/query and serialized liteserver submissions sharing one work budget | `test-ext-message-manager` |
| Profile parsing and options validation | `test-validator-options` |
| Engine option registration and duplicate-option rejection | `scripts/check-ext-message-work-cli.py` |
| Test sensitivity to setter, parsed-profile and hash-format guards | `scripts/check-ext-message-options-controls.py` |

For a native checkout, build the four test targets and `validator-engine`, then
run the CLI probe with `--engine BUILD/validator-engine/validator-engine` and an
external `--output-dir`. Run the options control script separately for
`--boundary setter`, `parser-validation` and `parser-canonical`, supplying
`--build-dir BUILD` and a separate output directory for each. The control script
temporarily edits the guarded source, rebuilds, requires the intended failure,
and restores/retests it. Do not run it alongside another build or source editor.

The CLI probe supplies `--help` after the profile arguments and checks diagnostics
as well as exit status: the engine intentionally exits with status 2 for help.
It does not start a node. Its success establishes parser wiring, not runtime
installation, network-origin coverage, calibration or release readiness.

The manager test retains the production submission handlers, liteserver parser
and cache, and shared pool. It substitutes startup with a frozen state and local
options, without databases or network listeners. Three malformed submissions
through different handlers consume a synthetic three-unit budget; subsequent
submissions through each handler, with null and rotating source identities,
observe the shared exhausted budget. `--manager-entrypoints` on the pool control
runner deletes shared charging and requires that test to fail. This does not
establish HTTP/ADNL transport coverage, actual signature rejection cost or mixed
network-load fairness.

The pool suite also executes a funded, non-special masterchain account from a
synthetic variant of the frozen fixture: only optional ConfigParam 31 is removed;
account code, balances and gas-price parameters remain unchanged. The
[recorded rejection](ordinary-work-20261006.json) reports `steps=13, gas_used=0`, while the VM start/finish counters each
equal one and the attempt consumes work. A targeted charge-deletion control
must fail this test. Basechain 20,000-credit calibration and full release genesis
acceptance remain separate gates.

## Explicit genesis candidate

A wrapper may define both `v5r2-network-tag` (the chosen public 256-bit AUTH
namespace) and `v5r2-admission-candidate` before including
`crypto/smartcont/gen-zerostate.fif`. This generates version 18 and basechain
ConfigParam 21 credit 20,000. Masterchain ConfigParam 20 stays at credit 10,000;
all other gas-price fields are unchanged. Omitting the candidate flag retains
the existing version-16 default or version-17 AUTH-only profile. The candidate
requires the namespace before any wallet key generation.

The [genesis evidence](admission-genesis-20261006.json) reads actual generated
BOCs and includes version/credit mutations and an early-namespace-guard deletion.
The separate localnet generator requires `v5r2_admission_candidate=True`, version
18, the deployment fee schedule and an explicit AUTH namespace. Its generated
ConfigParam 20/21 cells match the canonical candidate byte-for-byte; incompatible
profiles fail before key generation. The localnet credit and validation bypass
controls are recorded in [localnet evidence](localnet-admission-20261006.json).

This is a configuration candidate for further acceptance work. Rust defaults, full wallet transaction parity under the generated
configuration, calibrated node rates and public-network activation remain
pending; generating a BOC does not establish these gates.

The [Rust loading controls](rust-admission-config-20261006.json) generate the
canonical candidate and pass its `ConfigParams` directly into
`BlockchainConfig::with_config`. Version and every gas field match the generated
configuration. Replacing basechain loading with the old default table fails at
credit 20,000 versus 10,000. The runner retains the public ConfigParams BOC for
transaction testing; this loading check does not execute wallet transactions.


## Falcon activation boundary

The candidate restores the design's version-19 gate for both dedicated
`F93101` and generic `F93102` suite 2. At version 18 they return `inv_opcode`
and `range_chk`, respectively. The C++ capability ceiling is 19; the explicit
V5R2 candidate genesis remains 18, and default genesis remains 16. Raising the
capability ceiling does not activate Falcon on those configurations.

[Boundary evidence](falcon-version-20261006.json) records 42 dedicated and 42
generic cases per VM over versions 0 through 20, with valid and invalid public
signatures. All four independent C++/Rust early/late gate mutations fail at the
intended boundary and restored builds pass. The 80-case four-suite version
corpus and 39-case frozen corpus retain exact cross-VM gas/result parity. The
Falcon client rejects version 18; its nine wallet boundary tests pass and a
version-18 provider mutation fails before restoration.

These are explicit-version opcode tests and local client tests. They do not
close G02's requirement to execute through the actual generated release
configuration, nor prove full transaction, network, hardware or deployment
acceptance. Previous version-16 Falcon development histories require their
original binary; this candidate is for a fresh development genesis.


## Transactions with the generated candidate configuration

The [generated-config transaction evidence](release-config-transactions-20261006.json)
uses the actual public ConfigParams BOC emitted by the canonical candidate test.
`Emulator.from_config` loads its dictionary directly; the Rust transaction driver
loads the same file without replacing ConfigParam 8 or any gas fields. A probe
contract reads version 18, basechain credit 20,000 and masterchain credit 10,000
before signature verification. The test runs after the canonical genesis time.

Ten real transactions cover valid/invalid signatures for generic suites 1–4
and the dedicated Falcon entry. ML-DSA, SLH and LMS valid cases update state;
invalid signatures and both Falcon entries preserve it. Native/Rust transcripts
agree on compute/action results, gas, outgoing messages, balance and data hash.
This probe emits no messages, so it is not recipient-delivery evidence.

Three sensitivity controls require failure for native synthesized-config fallback,
removed signature verification and Rust default-config fallback. The last
control fails inside the contract with exit 904 (basechain credit mismatch).
All sources and binaries are restored, and all ten transactions pass again.
The older 67-transaction version-17 wallet recovery corpus also remains unchanged
in both execution paths; those older transactions still use diagnostic fixtures.

This closes a configuration-plumbing and version-18 instruction-execution gap.
The probe is not the V5R2 wallet: full wallet AUTH/POP/preparation/recovery,
post-rotation recipient payment and the complete worst-case external admission
corpus must still run using the generated configuration and aligned identities.


## Selected full-wallet corpus on generated configuration

The [full-wallet corpus evidence](release-wallet-20261006.json) loads the same
canonical version-18 ConfigParams BOC unchanged in both transaction executors.
Module identity, vault identity and signature domains use its ConfigParam 19
global ID and ConfigParam 48 AUTH namespace. Transaction time is after the
canonical genesis. Funding amounts are calculated from the generated compute,
forwarding and storage tariffs; no gas credit or protocol tariff is changed.

The corpus covers 26 AUTH fee-delivery transactions, 24 primary POP transactions,
24 SLH POP transactions and 64 recovery transactions. The recovery flow locks
PRIMARY, deploys a fresh module and fee vault, proves both successor keys,
installs the new tuple at the existing wallet address, rejects the old route and
pays the recipient through the new route. Recipient data and balance changes are
checked. PRIMARY signs POP only during recovery; all spending uses SLH and LMS
pays the fee route. No classical signature is required.

Deleting the lock retirement update or migration module update must fail at the
specific wallet state-transition assertion. These mutations occur only in
private contract copies. The durable runner is
`test/wallet-v5r2/release_wallet_corpus.py`; `--controls` includes both deletions.

Initial funded account states are synthetic; successor deployments and all
following action phases execute as real emulator transactions. This is a
selected local corpus, not full worst-case admission clearance, actual-network
acceptance or installed-enrollment CLI custody acceptance. SDK deployment and cached-signature coverage is recorded separately below.
Proof-provider and installed-enrollment CLI custody acceptance remain open.


## SDK enrollment, deployment and cached recovery

[SDK evidence](release-sdk-20261006.json) passes the generated global ID,
AUTH namespace and version through the enrollment encoder and public fixture
fee signer. The actual journal route is checked on signing and retry responses.
Dropping either configured identity in the Rust fixture driver must fail the
cache helper's route assertion; restored driver builds pass again.

The SDK builds matching initial StateInit cells and deploys wallet, module and
vault in emulator transactions. Complete preparation and fee envelopes are
compared against independently constructed cells. Recovery uses six persistent
native LMS signatures across old/new journals; retries return identical bytes
without another signer invocation. Wrong intents/keys, restart signing during
the wait barrier and corrupted backend output are rejected. Both successor POP
roles, wallet migration and payment through the new route complete; 67 whole
transactions match between the native and Rust executors with the unchanged
candidate configuration.

This is local SDK and transaction evidence using public deterministic test
keys and controlled fixture time. Initial funding messages are constructed by
the harness. Proven-chain migration custody, installed-enrollment CLI promotion,
real backup-derived keys, live funding/finality and production acceptance remain
open gates. The old diagnostic fixture defaults are retained for historical
regression; generated-config tests pass explicit identity and version values.


## Complete ordinary-account execution bound

The gas helpers distinguish initial credit from complete execution.
`external_tvm_complete_gas_bound` includes ordinary `gas_limit` after `ACCEPT`,
as well as special-account initial limit plus credit. It rejects unsupported
signed ranges and uncalibrated precompiled profiles. These helpers are not
connected to runtime work-unit pricing and do not set a production rate.

[Post-ACCEPT evidence](post-accept-20261006.json) runs five transactions through
both executors using the unchanged generated version-18 configuration. An
ordinary funded owner-controlled account without ACCEPT is rejected. With
ACCEPT, the same class of loop consumes 116,106 gas, and exhaustion consumes
30,000,000 gas. The exhausted transaction preserves data while charging compute
fees; all native/Rust transcripts agree. The account is a probe, not a wallet.

Deleting ACCEPT fails the expected-acceptance assertion. Replacing the complete
gas bound with the initial bound fails the C++ ordinary-account assertion;
restored unit tests pass. Full block transaction execution must cover post-ACCEPT paths. Node admission
sets `stop_on_accept_message=true` and stops at ACCEPT (or SETGASLIMIT), so its
CPU quote covers work up to that stop, parsing, state lookup, serialization,
instruction overshoot, special accounts and supported native execution. The
selected wallet fee maximum of 15,556 is not a bound for every destination.
Actual checker behavior is recorded below; hardware/network calibration remains
open. The complete gas helper above applies to full transactions, not the
stop-on-accept checker.


## Actual checker stop-on-accept boundary

[Checker evidence](checker-stop-accept-20261006.json) corrects the distinction
between full transaction execution and node admission. Production
`ExtMessageQ::ExecutionConfig::create` sets `stop_on_accept_message=true`.
Both ACCEPT and SETGASLIMIT use the VM's stop path. The checker does not execute
the post-ACCEPT loop that the full-transaction probe measures above.

The real pool/checker test uses a synthetic variant of the frozen masterchain
state. It removes optional ConfigParam 31 and replaces an ordinary funded
account's code/data with the frozen public probe. It retains the original
balance, address and gas-price configuration. The accepted probe consumes 436
gas against initial credit 10,000 and executes the VM exactly once. It consumes
one shared work unit; a malformed request consumes the second; subsequent local
and peer submissions are refused. Byte occupancy releases after each request.

Disabling the production stop flag executes the loop to 116,106 gas and fails
the stop-marker/gas assertions. Deleting shared charging fails the budget
exhaustion assertion. Restored full pool tests pass. The earlier 30,000,000 full
transaction result remains valid, but must not be used as the ordinary
stop-on-accept checker execution bound. Initial credit alone still does not
price parsing, lookup, serialization, overshoot or special/native execution.

This establishes a real checker boundary on a synthetic frozen configuration;
version-18 generated-state checker coverage, SETGASLIMIT-specific runtime
coverage and hardware/network CPU calibration remain open.
