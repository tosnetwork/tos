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

For the multi-nominator path specifically, `nominator-pool/pool.fc:142` parses
the same pool-order field sequence as the single-nominator pool and `:669`
relays those terms unchanged to the controller. This is why the shared
production builder applies, even though the lifecycle script is not a
single-nominator test.

The exact classical Fift dependency inventory is maintained by
`scripts/check-classical-stake-callers.py`. It currently contains nine
executable files, including the base tools and legacy fixtures. The count is
not a count of nine launch-facing failures, and reducing it by deleting a
textual reference does not demonstrate a working replacement.
