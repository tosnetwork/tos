# TOS Validator-Led Distribution and Bootstrap Economics

**Status:** Draft implementation candidate; production launch gates remain open<br>
**Version:** 0.6<br>
**Date:** August 12, 2026<br>
**Target activation:** New mainnet genesis after all launch gates in Section 14 pass

**Version 0.6 revision note:** Version 0.5 routed essentially the entire
five-billion-TOS supply target through validator block rewards. Version 0.6 is
a deliberate monetary-policy revision: validator block rewards are recalibrated
to create approximately **500 million TOS**, and the remaining approximately
**4.5 billion TOS** community-agent allocation is created later through a
separate protocol reward mechanism (the Artificial Intelligence Proof of Work, AIPoW,
community distribution), which is specified outside this document, is not funded at
genesis, and is never held by any treasury wallet. Everything else in this
document — the bootstrap procedure, genesis balances, election parameters,
reward routing, non-mechanisms, and transparency rules — is unchanged in
structure and applies to the validator reward stream only.

## 1. Purpose and status

This document specifies a deliberately simple native-token bootstrap and
validator-reward policy for TOS.

The design preserves the protocol's existing mechanisms:

- the original validator set is committed in the zerostate;
- a bounded genesis main wallet funds the first validator elections;
- ConfigParam 14 creates native block rewards;
- collected rewards and fees are routed to the active validator set;
- the Elector distributes bonuses in proportion to effective stake; and
- ordinary configuration governance can change or stop future block rewards.

The design does **not** introduce a new emission state machine, a new time
authority, a missed-emission debt, or a per-validator work-proof protocol.
Seven years and five hundred million TOS of validator creation — within the
network's five-billion total-supply policy — are planning targets, not new
consensus invariants.

The policy commitments are:

1. Zerostate contains four equal-weight original validators.
2. Genesis creates only the two system-contract reserves and a narrowly
   bounded main-wallet bootstrap balance.
3. The main wallet may fund only 20,000 TOS of first overlapping-election
   stake principal for each original validator, plus a measured and capped
   bootstrap fee allowance.
4. There is no proof-of-work giver and no large main-wallet premine.
5. Approximately 500 million TOS is created through ordinary validator block
   rewards; the remaining community-agent allocation is created through a
   separate protocol reward mechanism specified outside this document and is
   not part of genesis or of the validator reward path.
6. The initial block-reward rate targets approximately five hundred million
   TOS of gross validator creation over approximately seven years.
7. Actual completion may occur earlier or later, and final gross validator
   creation may be modestly above or below five hundred million TOS.
8. A network outage creates no reward debt. No skipped reward is backfilled.
9. Reward creation is stopped or tapered through the existing configuration
   governance process when the public supply target is approached.

The implementation branch replaces the legacy main-wallet premine and
one-validator bootstrap with the genesis balances and validator parameters in
this document. ConfigParam 14 remains provisional until the sustained
calibration and complete election/reward recovery rehearsals in Sections 6 and
14 pass. No production zerostate hashes may be frozen before every launch gate
is closed.

## 2. Economic character of TOS

TOS is the native network token used to:

- pay transaction, message, storage, and protocol service fees;
- bond validators and secure consensus;
- compensate elected validators for operating and validating the network;
- settle native smart-contract and TOS Network service transactions; and
- participate in protocol governance where the protocol grants that function.

TOS does not represent:

- equity, debt, a partnership interest, or ownership of a legal entity;
- a claim on project assets, revenue, profits, dividends, or cash flows;
- a right to redemption by a company, foundation, or operator;
- a guaranteed return, fixed yield, or price-support commitment;
- a contractual right to managerial efforts intended to increase token value;
  or
- ownership of a model, terminal, data set, service provider, or other
  off-chain business asset.

Validator rewards are variable protocol payments. A validator must be elected,
remain eligible, operate the required infrastructure, and be subject to the
protocol's fault and penalty rules. Stake determines effective validator weight
and the validator's proportional share of the active set's bonus pool.

## 3. Supply policy

### 3.1 Policy targets

| Parameter | Version 0.6 policy |
|---|---:|
| Smallest unit | 1 nanotomi |
| Unit conversion | 1 TOS = 1,000,000,000 nanotomi |
| Approximate total network supply target | 5,000,000,000 TOS |
| Approximate validator-reward creation target | 500,000,000 TOS |
| Community-agent allocation (separate mechanism, out of scope here) | 4,500,000,000 TOS |
| Provisional main-wallet genesis balance | 100,000 TOS |
| Elector genesis reserve | 500 TOS |
| Configuration-contract genesis reserve | 500 TOS |
| Provisional total genesis supply | 101,000 TOS |
| Reference post-genesis validator creation | 499,899,000 TOS |
| Proof-of-work giver allocation | 0 TOS |
| Team, investor, foundation, and ecosystem allocation | 0 TOS |
| Protocol treasury allocation | 0 TOS |
| Target validator distribution duration | Approximately 7 years |
| Treatment of outages | No creation and no later catch-up |
| Reward termination | ConfigParam 14 is tapered or set to zero through configuration governance |
| Hard protocol supply cap | None added by this proposal |

The community-agent allocation is a policy target only. It is not created at
genesis, is not held by any wallet, and is not distributed through ConfigParam
14 or the Elector. Its reward mechanism, eligibility, and anti-abuse rules are
specified in the separate Artificial Intelligence Proof of Work (AIPoW) community
distribution design
and must pass their own launch gates before any of that allocation is created.

The main-wallet amount is provisional until the four-validator, two-overlapping-
election test has measured actual wallet, message, election, and recovery
costs. The final value must be the smallest audited amount that safely completes
that test, rounded up by a disclosed operational margin.

The reference arithmetic is:

```text
provisional_genesis_supply =
    100,000 TOS main wallet
  +     500 TOS Elector reserve
  +     500 TOS Configuration reserve
  = 101,000 TOS

reference_post_genesis_validator_creation =
    500,000,000 TOS validator-reward target
  -     101,000 TOS provisional genesis supply
  = 499,899,000 TOS
```

This identity is a calibration target, not a block-validity rule. ConfigParam
14 creates a fixed amount for each produced block. Actual block cadence,
validator availability, shard activity, configuration activation delay, and
the eventual stop transaction determine the final result.

### 3.2 Gross, outstanding, and circulating supply

The following values must be reported separately:

- **gross native creation:** every TOS created in zerostate or by block
  creation, including TOS later burned;
- **outstanding supply:** gross native creation minus provably burned TOS;
- **circulating supply:** outstanding TOS excluding protocol reserves, locked
  stake, and other publicly defined non-circulating balances; and
- **validator block creation:** cumulative ConfigParam 14 native creation after
  genesis.

Burning the unused bootstrap balance reduces outstanding and circulating
supply but does not erase it from gross native creation.

### 3.3 No exact cap or exact deadline

Version 0.6 intentionally does not add:

- a `validator_emission_issued` consensus counter;
- a supply-target rejection condition;
- calendar-year emission tranches;
- anniversary-bound reward logic;
- a new consensus-time commitment;
- `pending_emission`;
- a catch-up or recovery queue; or
- an automatic seventh-anniversary stop.

If the network creates blocks faster than forecast, the target may be reached
in less than seven years. If blocks are slower or the network is unavailable,
the target may take longer than seven years. If governance activation occurs
slightly before or after the target, final gross validator creation may be
slightly below or above five hundred million TOS.

These deviations must be measured and published. They are not protocol faults
under this specification.

## 4. Genesis bootstrap

### 4.1 Genesis accounts

The production zerostate contains three native-balance categories:

1. **Elector reserve:** exactly 500 TOS;
2. **Configuration-contract reserve:** exactly 500 TOS; and
3. **main-wallet bootstrap balance:** provisionally 100,000 TOS, subject to
   the test-derived reduction rule in Section 3.1.

No giver, test faucet, team wallet, investor wallet, foundation wallet,
ecosystem wallet, market-making wallet, or general treasury receives a
production genesis allocation.

The main wallet is a temporary bootstrap funding mechanism, not a protocol
treasury. Its address, code hash, controller policy, initial balance, intended
transfers, actual transfers, and final disposition must be published before
genesis.

### 4.2 Original validator set

The zerostate commits exactly four original validators in the initial
validator-set configuration. Each entry has:

- a unique validator signing public key;
- a unique ADNL identity;
- equal initial consensus weight;
- a published controlling masterchain wallet;
- a published operator identity and control disclosure; and
- a published network, hosting, geography, and software-client disclosure.

The original validator set is authorized by the zerostate and therefore does
not need to win an election before producing the first blocks. This is only a
bootstrap authorization. The first ordinary Elector result replaces it.

The original-set validity interval must be long enough for:

1. main-wallet funding transfers to finalize;
2. all four validator wallets to submit valid bids;
3. the first election to open and close;
4. the Elector to install the elected set; and
5. operators to recover safely from at least one failed transaction or restart.

The current 3,000-second generator value must not be reused without an
end-to-end timing proof. The final interval must be derived from ConfigParam 15
and the measured bootstrap procedure.

### 4.3 Main-wallet funding plan

With a 10,000 TOS minimum stake, uninterrupted participation in overlapping
elections requires two stake principals per validator:

```text
per_validator_principal =
    2 * 10,000 TOS
  = 20,000 TOS
```

The agreed economic bootstrap allocation is 20,000 TOS of stake principal per
original validator. An exact 20,000-TOS wallet balance cannot safely submit two
10,000-TOS stakes because wallet messages and Elector admission also consume
fees. The provisional operational transfer therefore keeps the principal at
20,000 TOS and adds a separately disclosed 100-TOS maximum fee and retry
allowance:

```text
per_validator_stake_principal     =  20,000 TOS
per_validator_fee_allowance       =     100 TOS
per_validator_bootstrap_transfer  =  20,100 TOS
four_validator_transfers          =  80,400 TOS
main_wallet_initial_balance       = 100,000 TOS
provisional_unspent_balance       =  19,600 TOS
```

The additional allowance is not stake principal or a validator reward. The
end-to-end bootstrap rehearsal must reduce it to the smallest amount that
reliably pays wallet deployment, election-message, Elector admission, and retry
costs. It may not exceed 100 TOS per validator in the production genesis plan
without a public specification revision and independent review.

Main-wallet transfers must:

- go only to the four published controlling masterchain wallets;
- not exceed the per-validator cap;
- use the same amount for every original validator;
- be ordinary, publicly visible on-chain transactions;
- contain no vesting, repayment, profit-sharing, or off-chain consideration;
  and
- complete before the first ordinary election closes.

After two overlapping elected validator sets have been installed successfully,
the remaining main-wallet balance must be transferred to a published
unspendable burn address. The main wallet must then retain zero spendable TOS.

If testing proves that a smaller initial balance is sufficient, all derived
figures in this document and the genesis supply tests must be reduced before
the production zerostate is frozen.

### 4.4 System-contract reserves

The Elector and Configuration balances are operating reserves:

- they are not validator stake;
- they are not validator rewards;
- they are not controlled by the main-wallet key;
- they may be spent only through the deployed system-contract code; and
- they are included in gross genesis supply.

The Elector needs native balance for tick-tock execution, confirmation
messages, stake returns, and validator-set installation. The Configuration
contract needs native balance for its protocol message paths. Their first
tick-tock cycles and all required outbound messages must succeed in a clean
zerostate test.

Ordinary election messages must attach sufficient value to pay their own
execution and response costs. The design does not create a new reserve
replenishment state machine.

### 4.5 First ordinary election

The intended transition is:

```text
zerostate original set
  -> main wallet funds four controlling wallets
  -> four wallets submit equal election stakes
  -> Elector selects and installs the first ordinary set
  -> the next overlapping election is funded
  -> unused main-wallet balance is burned
  -> recurring permissionless elections continue
```

There is no 30-day zero-stake reward period and no automatic day-31 or day-91
stake-tier transition.

## 5. Validator and election parameters

### 5.1 Initial production parameters

| Parameter | Proposed value | Purpose |
|---|---:|---|
| Validation epoch | 65,536 seconds | Retain the existing election cadence |
| Election starts before next epoch | 32,768 seconds | Prepare the next set while the current set is active |
| Election ends before next epoch | 8,192 seconds | Leave time to install the next set |
| Stake hold after epoch | 32,768 seconds | Preserve complaint and penalty handling |
| Minimum validators | 4 independent operators | Minimum equal-weight bootstrap and recovery set |
| Recommended public-launch target | 64 independent operators | Reduce initial operational concentration |
| Long-term target | At least 75 eligible validators | Broaden recurring elections |
| Maximum validators | 400 | Bound election and consensus overhead |
| Maximum masterchain validators | 100 | Bound masterchain consensus overhead |
| Validators per shard group | 23 | Retain the current shard-group target |
| Minimum stake per validator | 10,000 TOS | Permit the first public elections while circulation is still limited |
| Maximum submitted stake | 10,000,000 TOS | Limit a single election entry |
| Minimum aggregate stake | 40,000 TOS | Four times the minimum stake |
| Initial maximum effective-stake factor | 1 | Keep a four-validator set equal-weight; §5.2 governs any increase |

The four-validator value is a hard protocol minimum, not a sufficient
decentralization target. Four equal-weight validators require three
participating signatures for a greater-than-two-thirds quorum. One unavailable
validator can be tolerated; two unavailable validators halt progress.

### 5.2 Effective-stake factor

The Elector does not weight a validator by the stake it submitted. It weights
the validator by what that stake is capped to
([`elector-code.fc:770`](../crypto/smartcont/elector-code.fc)):

```text
true_stake = min(stake, (max_stake_factor * smallest_elected_stake) >> 16)
```

The surplus above the ceiling is refunded rather than staked. ConfigParam 17
holds the factor in units of 1/65536, and genesis sets it to 65,536 — a factor
of one — so every elected validator carries the weight of the smallest one and
a four-validator set is equal-weight no matter what its members submitted.

Version 0.6 adds no validator-count-dependent factor formula to the Elector.
Raising the factor is an ordinary configuration change, not an automatic
consensus rule.

**The bound.** The factor decides how much heavier the largest entry may be
than the smallest, so the worst case is one entry staking to the ceiling while
every other sits at the minimum:

```text
worst_case_share = factor / (factor + min_validators - 1)
```

Holding that share below one third — the point at which a single party can
stall consensus alone — is the whole rule:

```text
factor < (min_validators - 1) / 2
```

| Factor | Smallest `min_validators` that permits it | Worst-case share of one entry |
|---:|---:|---:|
| 1 | 4 | 25.0% |
| 1.5 | 5 | 27.3% |
| 2 | 6 | 28.6% |
| 3 | 8 | 30.0% |
| 5 | 12 | 31.25% |
| 7 | 16 | 31.8% |

The factor is not an independent knob. Upstream's value of three is harmless on
a set of 350 and hands one entry half the weight on a set of four, so it cannot
be copied on its own.

**The order.** `min_validators` moves first, in a separate proposal that
activates before the factor's. The bound is measured against the smallest set
the *configuration* permits, not against the set that happens to be running:
raising the factor first opens a window in which the configuration allows a set
where one entry holds half the weight, and the Elector may install exactly such
a set during that window. Raising the floor first only makes elections
stricter, which is never a safety loss.

**The tooling refuses the wrong order.**

```bash
# 1. Check the combination before writing any proposal.
scripts/check-stake-factor-safety.py --factor 3 --validators 8
scripts/check-stake-factor-safety.py --zerostate state.boc   # against live config

# 2. Raise the floor. Refuses a floor the current set cannot absorb an
#    absence under (--margin, default 2 validators).
scripts/propose-validator-count.sh --state state.boc --min-validators 8

# 3. Only once that proposal has activated, raise the factor. Refuses to emit
#    a signable proposal while the floor does not support the value.
scripts/propose-stake-factor.sh --state state.boc --factor 3
```

**The remaining preconditions are policy, not arithmetic.** Governance may
raise the factor only after:

- at least the new `min_validators` independently controlled operators — eight,
  for a factor of three — have remained elected across two consecutive sets;
  passing the arithmetic with keys that share effective control satisfies
  nothing (§5.3);
- common control and delegation concentration have been measured publicly; and
- the change passes election simulation and safety review.

**Reading the live values.** `/explorer/staking` reports `max_stake_factor`,
the smallest stake actually elected, the effective ceiling the two imply, and
whether a surplus above that ceiling earns. A surface that shows a stake beside
a reward rate without them describes a return the next unit staked will not
receive.

**What the factor gates.** While it is one, aggregating stake earns nothing at
the margin: a pool holding ten times the minimum is paid exactly what a solo
validator at the minimum is paid. That is why the pooled-stake contract ships
operable but without a user-facing entry point — see
[ADR-0002](adr/0002-pooled-stake-belongs-below-the-protocol.md).

### 5.3 Independence requirements

Four keys are not four independent operators if they share effective control.
Before genesis, the launch record must disclose:

- beneficial and operational control;
- funding source;
- signing-key custody;
- cloud or hosting provider;
- autonomous-system and network concentration;
- geographic concentration;
- software build and client diversity; and
- any founder, employee, investor, or service-provider relationship.

Common control remains a risk even when protocol keys and wallets are
different.

## 6. Validator block rewards

### 6.1 Existing reward path

Native validator issuance uses the existing block value-flow and Elector
architecture:

```text
ConfigParam 14 block-creation values
  -> native value recorded as created for produced blocks
  -> created value and collected protocol fees reach the configured collector
  -> the collector defaults to the Elector when ConfigParam 3 is absent
  -> the Elector credits the active validator set's bonus pool
  -> stake and bonuses are returned after the applicable hold period
```

The production genesis and integration tests must confirm the complete route.
It is not sufficient to observe `funds_created`; the test must prove that the
corresponding bonus reaches the correct active election and is recoverable by
validator controlling wallets.

### 6.2 Stake-proportional allocation

The existing Elector bonus formula is retained:

```text
validator_bonus_i =
    floor(total_set_bonuses * effective_stake_i / total_effective_stake)
```

The existing deterministic remainder handling is retained. The proposal does
not introduce a separate proposer bonus, work score, vote counter, assignment
commitment, participation commitment, or reward Merkle tree.

Validators do not earn merely because a wallet holds TOS. They must:

- submit a valid election bid;
- be selected into the active set;
- keep stake locked for the required period;
- operate the validator and assigned shard responsibilities;
- remain subject to complaints and penalties; and
- recover stake and bonuses through the existing Elector interface.

### 6.3 Approximate seven-year calibration

Using the provisional genesis values and an August 1, 2026 reference start,
the post-genesis validator creation target is:

```text
499,899,000 TOS
```

Across the 2,557 days from August 1, 2026 to August 1, 2033, the explanatory
average is approximately:

```text
195,502.15 TOS per day
2.26276 TOS per second
```

These numbers do not appear in block validation. They are used only to
calibrate ConfigParam 14 from observed production behavior.

Let:

- `lambda_mc` be the measured finalized masterchain blocks per second;
- `R_mc` be the masterchain creation value in ConfigParam 14;
- `lambda_s` be the measured finalized block rate of shard `s`;
- `depth_s` be that shard's prefix depth; and
- `R_bc` be the basechain creation value in ConfigParam 14.

The expected creation rate is:

```text
expected_TOS_per_second =
    lambda_mc * R_mc
  + sum_over_shards(lambda_s * R_bc / 2^depth_s)
```

The initial values of `R_mc` and `R_bc` must be selected from a sustained
multi-node measurement, not from an assumed block interval. The calibration
report must include:

- masterchain and workchain finalized block rates;
- empty and non-empty block rates;
- validator downtime;
- shard split and merge behavior;
- the chosen masterchain-to-basechain reward ratio;
- projected one-, three-, five-, and seven-year creation; and
- sensitivity to faster and slower production.

The implementation candidate uses:

```text
R_mc = 0.569879384 TOS
R_bc = 0.335223167 TOS
```

These values retain a 1.7:1 masterchain-to-basechain ratio and project
499,899,000.147912 TOS over 2,557 days at the locally measured 2.5
masterchain and 2.5 unsplit-basechain blocks per second. These values remain
candidates until their derivation, one-offline-validator behavior, and
sensitivity to sustained multi-host production are independently verified and
launch gate 11 is closed.

### 6.4 Outages and restarts

Issuance is event-based:

```text
no finalized produced block -> no ConfigParam 14 creation
```

An outage, standstill, partition, failed election, or delayed restart does not
create `pending_emission`. When production resumes, each new block receives
only the ordinary creation amount then in effect.

There is:

- no backfill;
- no catch-up multiplier;
- no first-block recovery reward;
- no outage debt;
- no missed-epoch queue; and
- no extension automatically added to a seven-year calendar.

### 6.5 Shards and block cadence

The existing basechain reward is divided by shard depth for each shard block.
If all shards at the same depth produce at similar rates, aggregate basechain
creation remains approximately stable as the workchain splits. Unequal shard
rates, delayed blocks, merges, or implementation behavior may still change the
actual total.

The supply dashboard must use finalized on-chain `funds_created` values rather
than estimates based only on wall-clock time or shard count.

### 6.6 Taper and stop procedure

There is no automatic supply stop in Version 0.6. Governance must manage the
end of the initial distribution using existing configuration proposals.

The recommended procedure is:

1. Publish cumulative gross creation continuously.
2. Publish projections based on trailing 30-, 90-, and 180-day block rates.
3. Begin a public taper review before projected gross validator creation
   reaches 495 million TOS.
4. Reduce ConfigParam 14 values if proposal activation delay could produce a
   material overshoot.
5. Set both masterchain and basechain creation values to zero near the
   500-million validator-creation policy target.
6. Publish the final gross, burned, outstanding, and circulating figures.

Transaction, storage, forwarding, and service fees continue after native block
creation is set to zero. Future inflation must not be implied by this
specification; any proposal to restart native creation is a separate monetary
policy decision requiring prominent public review.

## 7. Fees, penalties, and burns

An active validator set's economic inflow may include:

```text
native block creation under ConfigParam 14
+ transaction and protocol fees assigned to validators
- valid penalties and burns
```

Only ConfigParam 14 native block creation increases gross native supply.
Transaction and protocol fees transfer existing TOS.

The existing complaint and penalty paths are retained. This proposal does not
create new slashing evidence, new reward eligibility proofs, or a new burn
replacement allowance.

Burned bootstrap funds, fees, and penalties are not automatically recreated.
The approximate 500-million validator target concerns gross validator
creation, while burns reduce outstanding supply.

## 8. Governance and custody

### 8.1 Main-wallet custody

The main-wallet controller can move genesis TOS and is therefore a temporary
high-risk authority. Before genesis:

- its public key, contract code, and recovery procedure must be published;
- signing material must be held offline;
- every allowed destination and maximum amount must be fixed in the launch
  manifest;
- no transaction may fund an undisclosed address; and
- all signed funding and burn messages should be prepared and independently
  verified before launch where operationally practical.

Main-wallet authority ends economically when its spendable balance reaches
zero. The wallet must not be reused as a treasury, fee collector, governance
fund, market-making account, or emergency mint authority.

### 8.2 Configuration governance

Configuration governance retains authority over:

- ConfigParam 14 block-creation values;
- validator-count parameters;
- stake limits and effective-stake factor;
- election timing;
- fee collector address where explicitly configured; and
- other existing configurable protocol parameters.

Every monetary configuration proposal must publish:

- old and proposed values;
- activation conditions and expected activation time;
- cumulative gross creation at proposal time;
- projected supply impact;
- proposer and voting addresses;
- validator votes; and
- the resulting on-chain configuration proof.

### 8.3 No hidden distribution paths

Production genesis and configuration must not fund or register:

- proof-of-work or test givers;
- faucets;
- discretionary mint contracts;
- team or investor vesting contracts funded with native genesis inventory;
- private fee collectors;
- undisclosed validator subsidies; or
- a general-purpose protocol treasury.

## 9. Protocol invariants retained

Version 0.6 relies on existing block and Elector validation. It adds no new
monetary consensus fields. The implementation must continue to enforce:

1. ConfigParam 14 determines the native amount created for each applicable
   produced block.
2. A block's value flow balances and its declared `created` amount matches the
   configured masterchain or depth-adjusted basechain value.
3. Only the configured collector receives recovered created value and
   applicable collected fees.
4. The collector fallback resolves to the Elector when ConfigParam 3 is absent.
5. The Elector associates bonuses with the correct active validator-set hash.
6. Elector bonus distribution is proportional to effective stake using
   deterministic integer arithmetic.
7. Invalid election bids, refunds, stake recovery, complaints, and penalties
   follow the existing contract rules.
8. A configuration change becomes effective only through the existing
   authenticated governance path.

The following are policy and genesis assertions rather than new block
invariants:

- four original validators;
- bounded main-wallet allocation;
- equal bootstrap transfers;
- no giver allocation;
- residual bootstrap burn;
- approximate seven-year duration; and
- approximate 500-million gross validator-creation target.

## 10. Explicitly rejected mechanisms

This version must not be implemented by adding any of the following:

- `EmissionSchedule`;
- `EmissionState`;
- `validator_emission_issued` as consensus state;
- `pending_emission`;
- a fixed recovery ring;
- anniversary tranches;
- a validator-emission debt;
- a consensus-time authority created only for token issuance;
- `WorkAssignmentCommitment`;
- `ParticipationCommitment`;
- per-validator reward work units;
- work-score reward allocation;
- a proposer-selected reward counter;
- automatic catch-up issuance after outages; or
- an automatic hard stop tied to a local or proposer clock.

Removing these mechanisms is a design requirement, not a deferred feature.

## 11. Required implementation changes

### 11.1 Zerostate generator

Update `crypto/smartcont/gen-zerostate.fif` to:

- replace the near-five-billion main-wallet balance with the audited bounded
  bootstrap balance;
- retain exactly 500 TOS for the Elector;
- retain exactly 500 TOS for the Configuration contract;
- include exactly four original validator keys and ADNL identities;
- assign equal initial validator weight;
- set `min_validators` to four;
- remove the current single-validator bootstrap profile;
- set the original-set validity interval from the tested election timeline;
- omit every production giver and faucet;
- print all genesis balances and total native genesis supply;
- fail if an unexpected genesis account has a native balance; and
- generate reproducible root and file hashes from the public manifest.

The generator currently comments that the base token is non-inflatable while
ConfigParam 14 creates native block value. That wording must be corrected so
source comments distinguish ConfigParam 7 extra-currency minting from
ConfigParam 14 native block creation.

### 11.2 Validator and stake configuration

Set initial production values to:

```text
ConfigParam 16:
  max_validators        = 400
  max_main_validators   = 100
  min_validators        = 4

ConfigParam 17:
  min_stake             = 10,000 TOS
  max_stake             = 10,000,000 TOS
  min_total_stake       = 40,000 TOS
  max_stake_factor      = 1          ;; 65,536 raw, units of 1/65536
```

`max_stake_factor` and `min_validators` are one parameter pair, not two
parameters: the factor is only valid against the floor, and the floor has to
move first. §5.2 gives the bound, the ordering, and the scripts that enforce
both.

Retain the existing ConfigParam 15 election cadence unless the full bootstrap
test proves a timing defect.

### 11.3 Block-reward configuration

- Measure finalized production rate on a four-validator test network.
- Select ConfigParam 14 values that project approximately
  499,899,000 TOS of post-genesis validator creation over seven years.
- Verify depth-adjusted basechain creation across split and merge tests.
- Verify the collector fallback or explicitly configure the Elector as fee
  collector.
- Exercise configuration proposals that reduce and zero both creation values.
- Do not add a new mint key or native mint transaction.

### 11.4 Main-wallet bootstrap

- Generate or import the published main-wallet key under the approved custody
  procedure.
- Create four controlling masterchain wallets separately from validator
  signing keys.
- Prepare equal funding transactions within the published cap.
- Complete and verify two overlapping elections.
- Burn the main wallet's remaining spendable balance.
- Publish transaction hashes and final zero spendable balance.

### 11.5 Elector

The intended implementation keeps the existing stake admission, election,
active-set bonus, stake return, complaint, and penalty logic.

No Elector change should be merged merely to implement:

- zero-stake elected validators;
- direct rewards to zerostate validator keys;
- work-score rewards;
- dynamic validator-count-based stake factors;
- pending issuance; or
- automatic issuance recovery.

If integration testing finds that the standard fee-collector-to-active-
election path is broken, that defect must be isolated and fixed with a focused
behavioral test. It must not be used as justification for a new reward
architecture.

### 11.6 Documentation migration

Before this specification becomes canonical, update every document that
describes:

- the current five-billion main-wallet premine;
- proof-of-work or giver distribution;
- genesis supply;
- validator reward availability;
- validator minimums and stake limits;
- original validator funding;
- exact supply-cap claims;
- exact seven-year release claims; or
- main-wallet custody.

At minimum, inspect:

- `doc/Currency.md`;
- `doc/Zerostate.md`;
- `doc/Validator-Local.md`;
- `doc/validator-genesis-bootstrap.md`;
- `doc/Validator.md`;
- `doc/tos.tex`;
- `doc/tos.pdf`;
- the repository `README.md`; and
- public website token and validator descriptions.

## 12. Test and audit requirements

### 12.1 Reproducible genesis

- Zerostate contains exactly the Elector, Configuration, and bounded main-wallet
  native allocations described in Section 4.1.
- No giver, faucet, team, investor, foundation, or treasury allocation exists.
- Exactly four original validators have equal weight.
- All four validator and ADNL keys match the signed launch manifest.
- ConfigParam 16 and ConfigParam 17 match Section 11.2.
- Genesis root hash and file hash reproduce from a clean build.
- Any one-nanotomi balance or key difference changes the expected artifact and
  fails the test.

### 12.2 Bootstrap funding

- The main wallet can fund all four controlling wallets.
- Every transfer is equal and within the published cap.
- Each transfer contains exactly 20,000 TOS of stake principal and no more than
  100 TOS of separately accounted bootstrap fees.
- No controlling wallet is the validator signing key itself.
- A fifth or substituted destination is rejected by the operational signing
  checklist and detected by the launch verifier.
- Wallet deployment, messages, retries, and two election stakes remain within
  the tested budget.
- The residual main-wallet balance is burned and the final spendable balance
  is zero.

### 12.3 Elections

- The original validator set produces blocks immediately after genesis.
- The original-set validity interval covers the complete first election.
- Four bids at the minimum stake satisfy the minimum aggregate stake.
- The first ordinary set is installed before the original set expires.
- A second overlapping election succeeds before first-round stake recovery.
- Failed, late, malformed, duplicate, and underfunded bids return the expected
  errors without losing unrelated principal.
- The four-validator effective set remains equal-weight with factor one.
- One unavailable validator does not halt a three-signature quorum; two
  unavailable validators do halt it without violating safety.

### 12.4 Reward routing and allocation

- Every produced masterchain block creates exactly the configured masterchain
  value.
- Every produced basechain block creates exactly the depth-adjusted basechain
  value.
- Created value and eligible collected fees reach the correct Elector active
  election.
- The Elector distributes bonuses proportionally to effective stake.
- Equal effective stakes receive equal rewards, subject only to deterministic
  integer remainder handling.
- Unequal effective stakes receive the exact existing proportional result.
- Penalized validators receive the expected stake and bonus adjustment.
- Reorganization and restart tests do not duplicate created value or Elector
  bonuses.

### 12.5 Issuance behavior

- Ten, one thousand, and one million simulated blocks produce the exact sum of
  their ConfigParam 14 creation values.
- A network outage produces no TOS.
- Restarting after an outage produces no catch-up reward.
- Faster block production increases creation per unit of wall-clock time.
- Slower block production decreases creation per unit of wall-clock time.
- Shard split and merge tests match the existing depth-adjustment rule.
- Updating ConfigParam 14 changes only blocks after activation.
- Setting both ConfigParam 14 values to zero stops new native block creation.
- Transaction and protocol fees continue to operate after block creation is
  zero.

### 12.6 Memory and denial-of-service

Version 0.6 adds no per-epoch emission queue, reward commitment, work proof,
or recovery ring. Tests must nevertheless confirm:

- no new unbounded in-memory state is introduced by supply telemetry;
- RPC label cardinality is bounded by known validators and shards;
- historical supply indexing is kept outside consensus hot paths;
- malformed election and reward-related messages do not accumulate; and
- long-running block creation, elections, restarts, and configuration updates
  show no unexplained anonymous RSS growth.

### 12.7 Independent review

Before production genesis, obtain:

- a reproducible-zerostate review;
- an Elector reward-path and stake-accounting review;
- a ConfigParam 14 creation and shard-depth review;
- a bootstrap-wallet custody and transaction review;
- a two-overlapping-election operational rehearsal;
- a multi-year issuance simulation using measured block-rate distributions;
  and
- an independent review of supply, burn, and dashboard accounting.

## 13. Transparency requirements

### 13.1 Genesis publication

Publish before launch:

- zerostate source and build instructions;
- zerostate root and file hashes;
- every genesis account and native balance;
- main-wallet code, address, controller policy, and transfer caps;
- four validator signing public keys;
- four ADNL identities;
- four controlling masterchain wallets;
- operator and common-control disclosures;
- ConfigParams 14, 15, 16, 17, 28, 29, and 34; and
- the signed bootstrap transaction plan.

### 13.2 Live supply dashboard

Expose:

- genesis gross creation;
- cumulative masterchain block creation;
- cumulative basechain block creation;
- cumulative gross native creation;
- provably burned TOS;
- outstanding supply;
- circulating-supply methodology;
- current ConfigParam 14 values;
- trailing block rates;
- projected target date under several block-rate windows; and
- every monetary configuration proposal and vote.

The dashboard must derive authoritative totals from finalized chain data. It
must label projections as estimates and must not display a guaranteed
supply cap or guaranteed seven-year completion date.

### 13.3 Validator dashboard

Expose:

- submitted and effective stake;
- active validator-set weight;
- elected periods;
- recovered principal and bonuses;
- penalties and complaints;
- known operator and controlling-wallet relationships;
- software version;
- network and hosting concentration; and
- top-1, top-4, top-10, and related-party effective-stake concentration.

## 14. Mainnet launch gates

Production genesis must not launch until:

1. The near-five-billion current main-wallet allocation has been replaced by
   the audited bounded bootstrap balance.
2. Exactly four original validators and four ADNL identities are committed in
   zerostate with equal weight.
3. `min_validators` is four and the initial effective-stake factor is one.
4. The Elector and Configuration contracts each have exactly 500 TOS.
5. No production giver, faucet, private treasury, or undisclosed genesis
   allocation exists.
6. The original-set validity interval passes the complete bootstrap timing
   test.
7. All four controlling wallets can fund two overlapping elections from the
   main-wallet cap.
8. The first and second ordinary elected sets install successfully.
9. The main-wallet residual burn procedure has been rehearsed and independently
   verified.
10. The full ConfigParam 14-to-Elector-to-validator reward path passes a
    deploy-and-execute test.
11. ConfigParam 14 has been calibrated from sustained four-validator block-rate
    measurements.
12. Outage, restart, faster-block, slower-block, shard-split, and shard-merge
    issuance tests pass.
13. Reducing and zeroing ConfigParam 14 through configuration governance has
    been demonstrated.
14. Supply accounting and dashboard values match an independent chain scan.
15. Long-running election and reward tests show no unexplained anonymous RSS
    growth.
16. All affected documents, generated white paper, README, and public website
    agree that 500 million TOS of validator creation (within the five-billion
    total-supply policy) and seven years are approximate policy targets.
17. The launch team publishes every known deviation from this specification.

## 15. Principal risks

### 15.1 Four-validator concentration

Four validators are sufficient only as a minimum startup set. They are not
evidence of broad decentralization. Common control, shared hosting, shared
software defects, or coordinated failure may halt or compromise the network.

### 15.2 Main-wallet authority

The main wallet is a temporary centrally controlled genesis account. A stolen,
misused, or unavailable key can disrupt bootstrap or redirect the limited
allocation. Public transaction caps, offline custody, prebuilt transactions,
independent verification, and rapid residual burning reduce but do not remove
this risk.

### 15.3 No hard supply cap

Configuration governance can change block rewards, and delayed action can
overshoot the supply target. Users must rely on transparent governance,
on-chain monitoring, and public policy rather than a newly introduced hard
cap.

### 15.4 Variable completion date

Block production is not a calendar clock. Network conditions can cause the
distribution to complete materially earlier or later than seven years.

### 15.5 Stake concentration

Stake-proportional rewards may compound ownership concentration. The initial
factor-one setting prevents unequal effective weight at the four-validator
floor but does not prevent one controller from operating multiple identities.

### 15.6 Long-term validator economics

After ConfigParam 14 is set to zero, validators depend on transaction, storage,
message, and protocol-service fees. Reward taper decisions must consider
network security and sustainable fee demand without implying a guaranteed
return.

## 16. Final design statement

TOS launches with four equal-weight validators committed in zerostate, two
500-TOS system-contract reserves, and a provisional 100,000-TOS main wallet
funded only for validator bootstrap. The main wallet supplies each of the four
controlling wallets with exactly 20,000 TOS of first-election stake principal
plus no more than 100 TOS of measured bootstrap fees, and burns the unused
balance.

After bootstrap, the network uses its existing block-creation, fee-collection,
Elector, staking, election, complaint, and reward-distribution mechanisms.
ConfigParam 14 is calibrated to create approximately 500 million TOS through
validator rewards over roughly seven years. Issuance follows actual block
production: outages are not backfilled, faster production releases TOS sooner,
and slower production releases it later.

The remaining approximately 4.5 billion TOS of the five-billion total-supply
policy is a community-agent allocation created through a separate protocol
reward mechanism (the Artificial Intelligence Proof of Work, AIPoW, community distribution). It is
specified outside this document, is not funded at genesis, is never held by a
treasury wallet, and must pass its own launch gates before any of it is
created.

Five hundred million TOS of validator creation, five billion TOS of total
supply, and seven years are transparent policy targets, not exact consensus
guarantees. No pending-emission debt, work-assignment commitment,
participation commitment, new consensus-time authority, or emission recovery
state is part of this design.
