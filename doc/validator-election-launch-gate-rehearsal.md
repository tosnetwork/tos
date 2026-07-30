# Validator Election Launch-Gate Rehearsal

**Status:** Test specification

**Date:** July 30, 2026

**Applies to:** The validator-led bootstrap and reward design in
[`tos-validator-only-token-economics.md`](tos-validator-only-token-economics.md)

## 1. Purpose

This document defines how a local TOS network can verify the remaining
validator-election launch gate:

- two complete, overlapping ordinary elections;
- activation of both elected validator sets;
- recovery of the first elected set's stake;
- recovery of the final elected set's stake and validator bonus; and
- continued consensus and bounded resource use throughout the exercise.

This is an end-to-end blockchain test. It must use real controlling wallets,
real validator signatures, real Elector messages, normal block inclusion,
ConfigParam 34 transitions, and normal stake recovery. Calling Elector
functions directly, rewriting contract storage, or advancing contract state
without producing blocks does not satisfy this launch gate.

The exercise has two complementary stages:

1. an accelerated functional rehearsal; and
2. an unmodified production-period rehearsal.

The accelerated rehearsal verifies the complete functional path in minutes.
The production-period rehearsal verifies that the same path remains correct
under the actual election timing. Passing only the accelerated rehearsal does
not close the production launch gate.

## 2. Repository Support and Remaining Harness Work

The repository already contains the principal transaction-building tools:

- `crypto/smartcont/validator-elect-req.fif`;
- `crypto/smartcont/validator-elect-signed.fif`;
- `crypto/smartcont/recover-stake.fif`;
- local validator, LiteServer, and DHT support in `test/tostester`; and
- Elector get methods including `active_election_id`,
  `participant_list_extended`, `compute_returned_stake`, and
  `past_elections_list`.

The local zerostate generator also supports four unique genesis validator
identities and the validator-economics profile.

There is not yet a single end-to-end harness that deploys and funds four
controlling wallets, submits two elections, polls both validator-set
transitions, recovers both rounds, and produces a machine-readable report.
That orchestration must be added before this specification can be executed
reliably and repeatedly.

## 3. Test Topology

### 3.1 Validator identities and wallets

Both rehearsal stages require:

- four unique validator public keys;
- four unique ADNL identities;
- four masterchain controlling wallets;
- sufficient funds in each wallet for its stake and transaction fees; and
- validator keys installed in the validator engines that will produce blocks.

The controlling wallet and the validator process are separate roles. A wallet
can submit an election request through any reachable LiteServer; it does not
have to run on the machine hosting the corresponding validator engine.

### 3.2 Using the existing three local nodes

The existing three-node local network can exercise the chain with a four-member
validator set in either of these configurations:

- install two validator identities in one validator engine; or
- keep the fourth validator identity intentionally offline and run with the
  remaining three of four validators.

The second configuration is useful for proving 3-of-4 liveness, but it is not a
substitute for the healthy 4-of-4 baseline. The recommended sequence is:

1. temporarily run four validator processes and complete the healthy baseline;
2. repeat with one validator offline while the other three continue; and
3. stop a second validator and confirm that the network halts safely rather
   than finalizing with only two of four validators.

A temporary fourth local process is sufficient for the baseline; it does not
need to become a permanent service node.

### 3.3 Single-host limitations

A local network can validate contract behavior, validator configuration,
consensus transitions, restarts, balances, and resource bounds. A single host
cannot validate:

- independent operator custody;
- geographic and provider diversity;
- realistic WAN loss, latency, and partitions;
- independent host clocks and clock drift;
- failure of an entire machine or data center; or
- operational coordination among unrelated validators.

The final pre-launch exercise must therefore be repeated on multiple hosts
under independent operator control.

## 4. Stage A: Accelerated Functional Rehearsal

### 4.1 Isolation requirement

Acceleration must be an explicit, test-only zerostate profile. It must not
change:

- Elector or Config contract code;
- ConfigParam 16 validator-count rules;
- ConfigParam 17 stake limits;
- wallet, signature, or message formats;
- validator selection and weight calculation;
- block-reward routing;
- bonus allocation;
- stake freezing and recovery logic; or
- any production generator default.

Only election timing and the initial validator-set lifetime may be shortened.
The resulting zerostate hash must be clearly labeled as non-production and
must never be reused for a public network.

### 4.2 Candidate accelerated timing

The following values are a practical starting point:

```text
elected_for        = 300 seconds
elect_start_before = 180 seconds
elect_end_before   = 60 seconds
stakes_frozen_for  = 180 seconds
initial_set_valid  = 600 seconds
```

These values provide a two-minute submission window while preserving a real
overlap between the next election and the currently active validator set. The
complete two-election and final-recovery path takes approximately 23 minutes,
plus setup and confirmation margin.

The harness must validate all ConfigParam 15 ordering constraints before
generating the zerostate. If the local block rate or transaction inclusion
latency cannot reliably fit within this schedule, the periods must be
increased rather than bypassing normal message processing.

### 4.3 Accelerated execution sequence

The harness must perform the following sequence.

1. Generate a test-only zerostate with four unique genesis validators.
2. Start the DHT, LiteServer, and four-validator baseline.
3. Wait until masterchain and workchain production are stable.
4. Deploy four real masterchain controlling wallets.
5. Fund every wallet with at least the intended stake plus transaction fees.
6. Record the initial wallet, Elector, Config, and total observable balances.
7. Poll `active_election_id` until the first ordinary election opens.
8. For each validator:
   - build the exact election request;
   - sign it with the validator key;
   - build the Elector message body;
   - submit the message through the controlling wallet; and
   - confirm acceptance through Elector state, not merely transaction
     inclusion.
9. Record `participant_list_extended` and verify all accepted keys, ADNL
   addresses, stakes, and maximum stake factors.
10. Wait for the first ordinary validator set to become active.
11. Read ConfigParam 34 and verify that its time range, validator keys, ADNL
    identities, weights, and total weight match the elected result.
12. While the first ordinary set's stake remains frozen, submit the complete
    second ordinary election.
13. Verify the second participant list and the second ConfigParam 34
    transition.
14. Wait until the first election becomes recoverable.
15. Query `compute_returned_stake` for each first-round wallet, submit
    `recover-stake`, and confirm the resulting wallet credits.
16. Wait until the second election becomes recoverable.
17. Confirm that validator bonuses have been assigned to the second election,
    query every recoverable amount, submit `recover-stake`, and confirm final
    wallet credits.
18. Submit a second recovery request for at least one wallet and verify that it
    cannot recover the same principal or bonus twice.
19. Reconcile balances and archive the complete test report.

The first and second rounds should use distinguishable validator keys or
recorded election identifiers so that an accidental observation of the same
state cannot be mistaken for two transitions.

## 5. Stage B: Production-Period Rehearsal

### 5.1 Required parameters

The production-period exercise must use the proposed production values without
time acceleration:

```text
elected_for        = 65,536 seconds
elect_start_before = 32,768 seconds
elect_end_before   = 8,192 seconds
stakes_frozen_for  = 32,768 seconds
initial_set_valid  = 131,072 seconds
```

It must also use the final candidate Elector and Config code, ConfigParam
16/17 values, validator-engine binaries, controlling wallet types, genesis
funding procedure, monitoring configuration, and operational runbooks.

### 5.2 Expected nominal timeline

The nominal schedule below is relative to the zerostate validator-set start
time. Actual transaction and activation timestamps must be taken from chain
state.

| Event | Relative time | Approximate elapsed time |
|---|---:|---:|
| First ordinary election opens | 98,304 s | 27 h 18 m 24 s |
| First ordinary election closes | 122,880 s | 34 h 08 m 00 s |
| First ordinary set becomes active | 131,072 s | 36 h 24 m 32 s |
| Second ordinary election opens | 163,840 s | 45 h 30 m 40 s |
| Second ordinary election closes | 188,416 s | 52 h 20 m 16 s |
| Second ordinary set becomes active | 196,608 s | 54 h 36 m 48 s |
| First-round stake becomes recoverable | 229,376 s | 63 h 42 m 56 s |
| Second ordinary set completes | 262,144 s | 72 h 49 m 04 s |
| Second-round stake and final bonus become recoverable | 294,912 s | 81 h 55 m 12 s |

The formal run therefore needs at least 82 hours from the relevant zerostate
time. A four-day minimum is appropriate, and a five-day reservation is
recommended to allow setup, delayed inclusion, restart recovery, final
reconciliation, and post-recovery observation.

### 5.3 Production-period procedure

Stage B repeats the complete Stage A transaction sequence, but:

- no election or validator-set time is shortened;
- wallets are controlled using the intended launch custody procedure;
- transactions are prepared and approved through the intended operator
  workflow;
- at least one planned node restart is performed during an open election;
- at least one validator is taken offline during a separately identified
  3-of-4 interval;
- memory, disk, block height, consensus participation, and Elector state are
  sampled continuously; and
- the network remains online for a post-recovery observation window.

The production-period run is invalid if an operator manually modifies
ConfigParam 34, Elector storage, account balances, election timestamps, or
node databases to force progress.

## 6. Balance and Reward Reconciliation

For every validator and election, retain:

- the wallet balance immediately before the stake transaction;
- the transaction value sent to the Elector;
- transaction and forwarding fees;
- the accepted and effective stake;
- the election identifier and validator weight;
- the bonus recorded for the completed validator set;
- `compute_returned_stake` immediately before recovery;
- the wallet balance after the recovery transaction; and
- the Elector balance and relevant credit dictionaries before and after
  recovery.

The recovered value must equal the contract-computed principal and bonus,
subject only to the chain's defined integer rounding and transaction fees.
The sum of credited validator bonuses plus any explicitly retained rounding
remainder must equal the bonus removed from the completed election.

The report must also reconcile newly created block rewards against the
observed Config and Elector transfers. An unexplained balance increase,
decrease, duplicated credit, or unrecoverable residual fails the rehearsal.

## 7. Failure and Recovery Cases

The accelerated suite must include the following cases. The production-period
run should repeat the cases marked operationally safe.

- a stake below ConfigParam 17's minimum;
- a total accepted stake below the minimum required for a valid election;
- duplicate participation from the same validator key or wallet;
- a request containing an old or incorrect election identifier;
- an invalid validator signature;
- a mismatched validator key, wallet address, or ADNL identity;
- a transaction submitted after the election closes;
- a validator-engine restart during an open election;
- a restart after election completion but before ConfigParam 34 activation;
- a restart after rewards arrive but before stake recovery;
- one validator offline, with three of four continuing;
- two validators offline, with the network halting safely;
- recovery before the unfreeze time;
- repeated recovery after a successful recovery; and
- recovery after all nodes restart from persisted state.

After every restart, the harness must prove that the chain resumes from the
same election state and does not duplicate a validator-set transition,
principal credit, or bonus.

## 8. Resource and Liveness Monitoring

Collect at least once per minute:

- masterchain and workchain head sequence numbers;
- finalized block age;
- active validator-set hash and time range;
- validator participation and missed slots;
- Elector account balance;
- current and past election counts;
- pending Elector credits and recoverable stake;
- process RSS and proportional set size where available;
- anonymous and file-backed memory;
- RocksDB size and write rate;
- CPU utilization, open file descriptors, and thread count; and
- process restart count and fatal/error log markers.

Election dictionaries, pending credits, actor queues, and anonymous memory must
return to a stable range after both recovery operations. Growth proportional
to completed elections without later cleanup is a failure even if the nodes
continue producing blocks.

The report must distinguish bounded caches, RocksDB memtable sawtooth behavior,
and persistent anonymous-memory growth. A short final RSS snapshot is not
sufficient evidence of bounded memory.

## 9. Required Evidence

Each run must preserve:

- source commit and dirty-worktree status;
- build identifiers and compiler configuration;
- zerostate root and file hashes;
- complete ConfigParam 15, 16, 17, 28, and 34 snapshots;
- validator public keys and ADNL identifiers, excluding private keys;
- controlling wallet addresses;
- signed transaction hashes and inclusion blocks;
- first and second election identifiers;
- participant lists and elected-set hashes;
- recovery transaction hashes;
- wallet and system-contract balance reconciliation;
- node logs and monitoring time series;
- restart and fault-injection timestamps; and
- a signed pass/fail report for every acceptance criterion.

Private wallet and validator keys must never be copied into the report.

## 10. Acceptance Criteria

The accelerated functional rehearsal passes only when:

- two distinct ordinary elections complete through normal on-chain messages;
- both elected sets become ConfigParam 34 in the expected order;
- the second election occurs while the first election's stake is still frozen;
- all eligible first-round stakes are recovered exactly once;
- all eligible second-round stakes and final bonuses are recovered exactly
  once;
- balances reconcile after fees and integer rounding;
- restart tests do not duplicate or lose state;
- 3-of-4 operation remains live and 2-of-4 operation halts safely; and
- memory and persistent election state remain bounded after cleanup.

The production-period rehearsal passes only when the same criteria hold using
the unmodified production timing and the final launch artifacts.

The production launch gate is closed only after:

1. the accelerated local rehearsal passes;
2. the unmodified production-period rehearsal passes;
3. the result is independently reviewed; and
4. an equivalent multi-host, multi-operator rehearsal confirms the operational
   assumptions that a single-host local network cannot test.

## 11. Non-Goals

This rehearsal does not prove:

- economic decentralization;
- legal or regulatory treatment of validator rewards;
- resistance to every Byzantine strategy;
- geographic fault tolerance from a single host; or
- the safety of future governance changes to election parameters.

Those concerns require separate analysis and must not be represented as
results of this test.
