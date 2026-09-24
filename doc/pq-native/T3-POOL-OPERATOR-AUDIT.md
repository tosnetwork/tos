# T3 pool-operator migration boundary

This is a source audit, not a live PQ staking result. T2's Stage A fixture is
complete; the paths below are different entry points and keep T3 open.

| Entry point | Actual consumer and current outcome | Migration boundary |
| --- | --- | --- |
| `crypto/smartcont/single-nominator-pool/validator-elect-signed.fif` | Builds the classical `validator-elect-req>B` preimage and 64-byte Ed25519 body. Its only executable reference in this tree is `crypto/test/test-smartcont.cpp`; no production launcher calls it. A user can still invoke the file directly and obtain a pool order that the PQ pool parser refuses. | The supported single-pool operator path must obtain `createPqStakeAuthorization` from the validator node and pass the bound public key/signature plus controller birth witness to production `nominator::new_stake_with_witness`. Retire or fail closed at the old Fift path only when that replacement is usable. |
| `scripts/nominator-pool-lifecycle-e2e.py` | Deploys `nominator-pool/pool.fc`, **not** `single-nominator-pool/single-nominator-code.fc`. Its primary pool stores the validator wallet as both operator and controller; its other validators send classical bodies directly to the Elector via the two base Fift tools. `stake_through_pool` currently refuses before sending. | A separate multi-nominator regression conversion: deploy admitted controllers, bind node PQ identities to their addresses before Genesis, send production PQ pool orders to the multi-nominator pool, and compare live ConfigParam 34 controller/ADNL identities. The multi-nominator pool already parses the same PQ order and relays to a controller. |
| `crypto/test/test-smartcont.cpp::run_validator_fift_script_regression` | Runs both base Fift tools and the single-pool Fift script with a fixed Ed25519 key, then checks bytes/BOC deserialization. It never sends to the current PQ pool, controller or Elector. | Preserve only as an explicitly named classical codec/parity fixture while its dependencies remain. Its green result is not evidence that any PQ stake is accepted. Move or remove it only in the later all-caller retirement change, together with the base Fift tools. |
| `crypto/test/fift/validator-proposal-{test,legacy-parity}.fif` | Both call the classical library word. | Retained executable legacy/parity fixtures, not launch operator paths. Their dependency must remain counted until a separate migration or self-contained legacy fixture replaces it. |
| `crypto/smartcont/liquid-staking/controller-elect-signed.fif` | Classical operator tool for a controller contract that still sends classical stake directly to the Elector. | Product is not launch-supported. Do not infer PQ support from a converted single- or multi-nominator pool. |

The first-stake witness is a separate operator-input requirement, not a field
supplied by `createPqStakeAuthorization`: its response contains validator ID,
key ID, algorithm, public key and signature. The controller relays the optional
witness it receives (`validator-controller-v1.fc:152,207`); the Elector returns
reason 8 for a first stake without it (`elector-code.fc:364`).
Both current tosctl pool-oriented callers use `nominator::new_stake`, whose
witness argument is `None` (`config_wallet_cmd.rs:582`, `runner.rs:756`,
`nominator/messages.rs:118`), so authorization alone cannot make their first
stake succeed. The diagnostic Stage A path obtains the witness from its
controller deployment fixture and uses `new_stake_with_witness`. The product
operator path needs a separately verified deployment-artifact witness source;
no contract or node-protocol change is implied by this audit.
The launch-facing defect is separately OPEN as
`pool-first-stake-birth-witness-missing` in
`N6-OPEN-CORRECTNESS-QUESTIONS.json`, with both tosctl callers named. Static
source conversion is not its closure; a first accepted stake and activated
live ConfigParam 34 are still required.

The two product callers need separate, inspectable witness handoffs:

| Caller | Missing source and transmission closure | Required product evidence |
| --- | --- | --- |
| `elections/src/runner.rs` | Resolve the configured controller's deployment artifact before the daemon builds its pool order; check that its derived address is the node-bound `validator_id` and its code hash is admitted by live ConfigParam 47; pass that artifact's birth witness to `new_stake_with_witness`. An absent or mismatched artifact must refuse locally. | The daemon's first real pool stake receives `STAKE_ACCEPTED`, followed by a live ConfigParam 34 pairing that controller ID with its ADNL. |
| `commands/src/commands/nodectl/config_wallet_cmd.rs` | Obtain the same verified deployment artifact for the interactive pool bid, rather than treating the node's authorization response as a witness; bind the witness to the configured controller and the destination pool, then pass it to `new_stake_with_witness`. An absent or mismatched artifact must refuse before sending. | The command's first real pool stake receives `STAKE_ACCEPTED`, and the controller appears in live ConfigParam 34. |

At exact source commit `ca842b0f1`, the interactive config-wallet caller met
its row's outcome on a co-located PQ chain: the command exited 0, the
stake-owner pool received exact `STAKE_ACCEPTED` for query ID `1790232216`,
and live ConfigParam 34 paired the configured controller with the ADNL from
the actual controller relay. The report SHA-256 is
`b5a448040fd75f5f55e206751f86831cf68b3c2de5d3f84fdca236e2447a693d`;
the raw and earlier failed-run evidence is in
`T3-CONFIG-WALLET-FIRST-STAKE-DIAGNOSTIC.md`. The daemon row is not satisfied
by this CLI run and remains the product witness/first-stake acceptance gap.

The multi-nominator lifecycle script is a different diagnostic consumer of
the production pool body. Its fixture can supply a witness, but neither its
static conversion nor Stage A's accepted stakes supplies the missing product
handoff for these two callers.

The shared Rust contracts crate now has a testable local refusal seam:
`nominator::new_stake_with_verified_controller_birth` accepts the controller's
*original deployment* `StateInit`, the node-bound validator ID, and an admitted
code hash obtained from live ConfigParam 47. It refuses absent code/data, a
non-code/data-only `StateInit`, a mismatched derived address, or a code hash
outside the supplied admission choice before building the fee-bearing pool
order. Its tests parse the resulting body and require the 544-bit witness in
the final reference; mutations that bypass either binding or omit the witness
fail. This is a pure verifier, not a live ConfigParam 47 reader. Passing a hash
copied from the artifact instead of one confirmed admitted on chain would
defeat the policy half. Both product callers now use the composed file-and-live-policy
entry point described below; the pure verifier alone is not their evidence.

Both product callers now share an optional, backward-compatible
`NodeBinding.controller_birth_state_init_boc` absolute-path locator. It names a
public artifact, not a key. Old configurations deserialize without it, but a
first stake then refuses locally; relative or unreadable paths also refuse.
`config bind add --controller-birth-state-init-boc` sets it, preserves it when
rebinding the same pool without a new value, and clears it when the pool
changes. This config command does not produce the artifact or deploy an
account.

`tosctl config --config CONFIG bind import-birth --node NODE
--transaction-boc DEPLOYMENT_TRANSACTION.boc --output /absolute/controller-birth.boc`
does produce the public artifact from an existing deployment transaction BOC.
It extracts the inbound message's original StateInit, requires a non-aborted
ordinary transaction that activates the account, checks the transaction
account and message destination against the pool's configured masterchain
controller, verifies the StateInit-derived identity, creates a new file without
overwriting one, and binds that path to the idle node. The transaction BOC can
be retained from the deployment receipt (`getTransactions` returns it as the
base64 `data` field, which must be decoded to a BOC file). This offline import
checks identity and shape; it does **not** independently prove that the supplied
transaction is finalized on chain. Both fee-bearing callers still require the
live ConfigParam 47 dictionary and matching node authorization.
The runner compares the node's authorization ID with `pool.get_roles()`; the
interactive command compares it with the controller in its configured SNP
pool. Both read live ConfigParam 47 as a raw cell through chain RPC, check
dictionary membership for the artifact's code hash, then use the verified
builder before constructing or sending a wallet message. The source guard pins
both callers to the live-policy read and verified builder. Rust negative tests
cover the runner's missing locator, the command's missing/relative locator,
and the shared builder's missing file, wrong controller and non-admitted code.
This is local refusal and assembly evidence, not a real first-stake result.

The operator must retain the original deployment `StateInit` BOC as a
public controller artifact associated with the configured binding. Reading a
controller's *current* account data cannot reconstruct its birth witness:
controller storage changes after deployment. Existing deployment commands do
not create or own this artifact; the operator imports the retained deployment
transaction, and the import command retains the extracted StateInit. No
deployment command or custody boundary was changed here. `pool liquid
controller create` is for unsupported liquid-staking, not a PQ controller
deployment precedent. A new PQ deployment command would need a separate review
of offline root-key and node consensus-key sourcing. The fixture's in-memory
StateInit is not a product source.
First accepted stakes plus live ConfigParam 34 remain the closure gate.

For the multi-nominator path specifically, `nominator-pool/pool.fc:142` parses
the same pool-order field sequence as the single-nominator pool and `:669`
relays those terms unchanged to the controller. This is why the shared
production builder applies, even though the lifecycle script is not a
single-nominator test.
Its accelerated economics Genesis must contain exactly four validators
(`zerostate.py:524`). The fifth controller-bound node therefore provisions PQ
custody without setting `is_initial_validator`; `Network._get_or_generate_zerostate`
filters on that flag when assembling Genesis. After boot, the node's
`get_local_pq_identity` requires a custodied signer and configured controller
identity but explicitly does not require present validator-set membership
(`validator-engine.cpp:5864-5879`), allowing the spare to authorize its first
pool stake for a later election. A unit test drives the actual network Genesis
filter with four initial identities and one noninitial spare. No live run has
yet confirmed the fifth candidate's election.

Before any network starts, the lifecycle preflight now accounts for known
Genesis faucet transfers and each pool's first two stake principals. The
ordinary profile commits 96,400 of the Genesis faucet's 100,000 TOS (3,600
TOS uncommitted); integrated mode commits 1,211,387 of 2,000,000 TOS. It
also refuses a support-wallet allocation below deployment plus two pool
principals and gas, or a primary wallet below deployment plus its own deposit
and stake gas. These are deterministic budget checks, not observations of
actual fees or chain balances. First-round acceptance remains tied to the
pool's Elector-acknowledged staked state, the target election ID and minimum
stake, then to a matching controller/ADNL pair in live ConfigParam 34.
Recovery requires a positive matured Elector credit before sending the
request, the pool returning idle with zero stake sent, and the Elector's
credit for that pool falling to zero afterward. No new live lifecycle run
has yet exercised those assertions.

### Bounded ordinary multi-nominator live run plan

This is the non-integrated sidecar, **not** the two-hour integrated campaign.
The accelerated election profile uses 300-second terms and the script waits
through an initial election, recovery/withdrawal and a later restake. Reserve
45–75 minutes wall time; individual 900-second election waits mean this is an
estimate, not a script-enforced deadline. A 75-minute supervisory cutoff must
report a partial run rather than a pass. Prior five-node diagnostic networks
retained 3.7–4.1 GiB; this six-process (one DHT plus five nodes) run gets a
**6 GiB run-directory ceiling**, with an early stop if root free space falls
below 8 GiB. Stop and preserve the partial directory at either limit—never
delete old completed networks to make it pass.

Use a fresh timestamped directory under `test/integration/.pq-nominator-pool-t3/`
with `--base-port 25000` (the harness allocates upward; expected 25001–25016).
The two orphaned historical DHT probes currently hold 21001, so do not use
the default 21000. Check the entire selected range with `ss` immediately
before starting and run no other network or native/Rust build concurrently.
The current native binaries and the production PQ pool-order example must be
built from the exact source commit being exercised; their existing timestamps
alone are not evidence of that. Capture the source commit, tracked-diff status,
binary hashes, manifest digest, report and raw network logs, then retain the
whole run directory. Do not launch at the present 16 GiB free merely because
the static checks pass: confirm the exact-head build and post-build free-space
margin first. This run can assess the multi-nominator diagnostic route; it
cannot close either tosctl product caller's first-stake witness question.

The exact classical Fift dependency inventory is maintained by
`scripts/check-classical-stake-callers.py`. It currently contains eight
executable files, including the base tools and legacy fixtures. The count is
not a count of eight launch-facing failures, and reducing it by deleting a
textual reference does not demonstrate a working replacement.
