# Post-zerostate installation experiment

**Historical experiment:** the coordinator subsequently selected genesis
installation and revised D40/D52. This preserves the failed runtime experiment
and D54 finding; it is not the current implementation plan. Current scope is
in `workchain-genesis-installation.md`.

Source reference: d51f962ff1a808bf48b9d5ca481cded4a5956102. Exact source and
binary hashes, generated inputs, commands and complete captured output are in
`doc/measurements/uno-two-config-install/`. This is a failed installation
experiment, not live acceptance. Existing uncommitted Counter shell migration
was present and is identified by hash; no production source was changed for
this experiment.

## Installation ordering constraint

`crypto/block/block.cpp:1936-1988` checks the final configuration transition.
A newly introduced ConfigParam 84 policy cannot be attached to a workchain
already present in the predecessor ConfigParam 12. Its new descriptor must
also have `accept_msgs=false`. Therefore this fixture must install the new
Param 12 descriptor and Param 84 shell in the same masterchain block, with
reception closed. Opening reception is a later transition. Installing these
two parameters in successive blocks is not a legal substitute.

The minimal experiment reuses `update-config.fif:36` and the existing signed
configuration contract (`config-code.fc:101,532`). Message one has seqno 0
and changes Param 12; message two has seqno 1 and changes Param 84. The disk
manager supplies them in that order (`manager-disk.cpp:717`). The isolated
zerostate contains neither Counter descriptor nor identity-bearing shell;
it gives the existing configuration contract a generated test key and funded
balance. The proposal tool obtains the completed zerostate representation
hash and emits configuration claims only, never a ledger.

## Observed result and stop

Both messages reached the same first masterchain candidate. The collator
passed its configuration transition and instance reconstruction code and
returned a candidate. This does not establish final validation success.
The final typed result was **CandidateReject**, with reason
`workchain 2 is active, but is absent from new shard configuration`.
The rejection originates at `validate-query.cpp:2371-2372`.

The final variant and its actual payload were observed in the
`CandidateReject` visitor at `manager-disk.cpp:324`, using a separate binary
with debug information added to that unchanged translation unit. In contrast,
`install.result.kind=success` describes collation only. Neither it nor GDB's
exit status is a final validation assertion. Two failed debugger setup runs
are retained and provide no typed-result evidence.

Source tracing explains the mismatch: `Collator::adjust_shard_config`
(`collator.cpp:1830-1852`) reads the installed predecessor configuration,
before the proposed configuration is installed at `create_mc_state_extra`.
The validator's shard coverage loop reads `new_config_`
(`validate-query.cpp:2316,2369`). This candidate introduces an active wc=2
that the earlier collator pass did not add to the shard configuration.
The validator rejects before its later configuration/ledger validation; that
later validation must not be claimed passed.

No check was weakened, no ledger injected, and no alternative installation
entry was added. This result does not establish that a new configuration
transaction mechanism is necessary. It identifies an additional shard
activation/construction dependency requiring a decision before claiming a
legal installation path.

## Revised work breakdown

The previous three-unit outline is no longer a demonstrated sufficient plan.
For scheduling, budget one additional decision-dependent unit before those
three: establish the permitted descriptor/shard activation transition and
prove a complete installation accepted by the validator. This is provisionally
four units, not a time estimate or a proven upper bound.

The remaining units are: complete the reusable legal installation fixture;
migrate the six consumer categories; then close the collator issuance-call
control and paired closed-configuration/live regression evidence. If resolving
the new stop requires a larger host change, the count must be revised before
consumer migration. No such change is implemented or implicitly authorized by
this experiment. Operator Rust decoding and other previously recorded
acceptance blockers remain unchanged.
