# Validator Election Stage A Local Result

**Date:** July 30, 2026

**Result:** PASS

**Scope:** Accelerated functional rehearsal defined by
[`validator-election-launch-gate-rehearsal.md`](validator-election-launch-gate-rehearsal.md)

## 1. Executive Result

The isolated Stage A network completed the validator-election path with no
test failures:

- two overlapping target elections were accepted and activated;
- a normal third rollover election retired the second target validator set;
- both target stakes and their validator bonuses were recovered through real
  controlling-wallet transactions;
- duplicate recovery did not pay twice;
- three of four validators preserved liveness;
- two of four validators halted safely and resumed after quorum was restored;
  and
- the sampled RSS and anonymous-memory curves showed bounded sawtooth behavior,
  not monotonic growth, during this 23-minute rehearsal.

This result closes Stage A only. It does not replace the unmodified
production-period Stage B rehearsal or a multi-host operator exercise.

## 2. Tested Build and Profile

The successful run recorded source commit
`78ca3219d474089982db707fcbc8604cd2662073` and the current working-tree
changes implementing the validator-economics profile and Stage A harness.

The test-only timing profile was:

| Parameter | Value |
|---|---:|
| `elected_for` | 300 seconds |
| `elect_start_before` | 180 seconds |
| `elect_end_before` | 60 seconds |
| `stakes_frozen_for` | 180 seconds |
| Initial validator-set lifetime | 600 seconds |
| Effective stake per validator | 10,000 TOS |
| Stake message value | 10,001 TOS |

The extra 1 TOS in the stake message covers the Elector's existing
confirmation deduction; the accepted effective stake remains exactly
10,000 TOS. ConfigParam 16, ConfigParam 17, contract code, validator selection,
weights, rewards, signatures, and wallet message formats were not accelerated.

The topology was one DHT process, one LiteServer endpoint, four validator
processes, four distinct validator keys and ADNL identities, four real
masterchain controlling wallets, and one separate negative-test wallet.

## 3. On-Chain Results

| Check | Evidence | Result |
|---|---|---|
| Initial validator set | Four unique public keys and ADNL identities; 600-second lifetime | PASS |
| Under-minimum stake | Rejected and returned to the negative-test wallet | PASS |
| Wrong election ID | Rejected and returned | PASS |
| Invalid validator signature | Rejected and returned | PASS |
| Duplicate validator key | Rejected without changing the accepted original stake | PASS |
| Minimum total stake | Three candidates produced 30,000 TOS and remained below the 40,000 TOS threshold; the fourth completed it | PASS |
| First target election | ID `1785451355`; four members; activated as ConfigParam 34 | PASS |
| Second target election | ID `1785451655`; submitted while first-round stake was frozen; activated as ConfigParam 34 | PASS |
| Rollover election | ID `1785451955`; funded from recovered first-round balances; activated through the normal Config/Elector path | PASS |
| Validator-set weight | Each elected set reported total weight `2^60` | PASS |
| Planned restarts | Open-election, post-election, pre-activation, and pre-recovery restarts recovered | PASS |
| Early recovery | Did not return principal before unfreeze | PASS |
| Duplicate recovery | Did not pay principal or bonus twice | PASS |

The four first-round wallets each recovered:

```text
12,087.479043163 TOS
```

This is the 10,000 TOS principal plus approximately 2,087.479043163 TOS of
validator bonus.

The four second-round wallets each recovered:

```text
12,050.367308204 TOS
```

This is the 10,000 TOS principal plus approximately 2,050.367308204 TOS of
validator bonus.

The rollover stake remains locked in the active rollover set by design and is
not treated as missing funds.

## 4. Consensus Fault Checks

With one validator stopped, the remaining three validators continued to
advance the chain and the stopped validator caught up after restart.

With two validators stopped, eight consecutive five-second observations all
reported masterchain seqno `3439`. No block was finalized with only two of four
validators. After quorum was restored, the chain advanced from `3439` to
`3442`.

The complete successful run advanced the sampled masterchain from seqno `13`
to final seqno `3442`.

## 5. Resource Observations

The monitor collected 142 samples from `22:32:46` through `22:56:24` UTC at
approximately ten-second intervals.

| Metric | Observed value |
|---|---:|
| Minimum mean RSS per running validator | 101,735 KiB |
| Maximum mean RSS per running validator | 352,763 KiB |
| Maximum individual-validator RSS | 380,344 KiB |
| Minimum mean anonymous memory per running validator | 66,592 KiB |
| Maximum mean anonymous memory per running validator | 317,588 KiB |

RSS repeatedly rose during block/database work and then returned to lower
levels; for example, a roughly 299-306 MiB band fell to roughly 189-198 MiB
before later cycles. Node restarts also reset the corresponding process
baseline. No unbounded or one-directional anonymous-memory trend was visible
within Stage A.

This short, single-host result is evidence against an immediate election-path
leak, not a long-duration leak proof. Stage B and post-recovery soak monitoring
remain required.

## 6. Harness Findings and Corrections

The rehearsal found two test-specification issues, neither of which was a
production-chain failure:

1. A fixed 240-second recovery polling window could expire before the second
   accelerated unfreeze time. The harness now derives its deadline from the
   election ID, elected period, and holding period, with confirmation margin.
2. Elector intentionally excludes its current `active_id` from unfreezing.
   Therefore the second target set cannot be recovered merely because its
   advertised time range elapsed. The specification and harness now require a
   successful rollover election and ConfigParam 34 activation before final
   second-round recovery.

The final successful execution included both corrections.

## 7. Supporting Checks and Artifacts

The following checks passed:

- Ruff validation and Python bytecode compilation for the Stage A harness;
- seven zerostate supply/profile tests;
- `git diff --check`;
- incremental builds of `validator-engine` and `test-smartcont`; and
- all 21 tests in `test-smartcont`.

The machine-readable local evidence is stored in:

```text
test/integration/.validator-election-stage-a/20260730T223235Z/
├── report.json
├── metrics.jsonl
├── artifacts/
└── network/
```

The directory is intentionally ignored by Git because it contains generated
keys, node databases, and approximately 5.2 GiB of ephemeral test data. The
final `report.json` has status `pass`, an empty `failures` array, all three
ConfigParam 34 snapshots, balance histories, and the complete event list.

The temporary Stage A processes were stopped after the report was written.
The existing persistent local DHT and three-validator services remained active
and were not used as the throwaway test network.

## 8. Remaining Launch Gate

Stage A is complete. The remaining launch gate is Stage B with unmodified
production timing, intended launch binaries and custody procedures, continuous
resource monitoring, and independent multi-host operators.
