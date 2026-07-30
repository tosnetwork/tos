# Local Validator Reward Calibration — July 30, 2026

## Status

This report records a local implementation calibration for the candidate
ConfigParam 14 values in
[`tos-validator-only-token-economics.md`](tos-validator-only-token-economics.md).
It is reproducible development evidence, not the independent sustained-network
confirmation required before production genesis.

## Test configuration

- Four equal-weight genesis validators in ConfigParam 34
- Four active validator-engine processes for the calibration interval
- One masterchain and one unsplit native basechain shard
- Simplex protocol version 2
- Target block rate: 400 ms
- Four slots per leader window
- ConfigParam 28 lifetimes: 250/250/1,000 seconds
- ConfigParam 28 shard validator target: 23, bounded by the four-member active
  set in this bootstrap network
- Empty-chain workload
- Local loopback transport on one Linux host

The network was generated with:

```bash
sudo env \
  VALIDATORS=4 \
  GENESIS_VALIDATORS=4 \
  VALIDATOR_ECONOMICS_PROFILE=1 \
  ./scripts/setup-testnet.sh --clean
```

All four lite servers reported identical finalized masterchain and basechain
heads throughout the sample.

## Measured finalized rates

After initial startup, heads were sampled every 30 seconds:

| Measurement | Start | End | Delta | Elapsed | Finalized rate |
|---|---:|---:|---:|---:|---:|
| Masterchain seqno | 86 | 1,213 | 1,127 | 451 s | 2.498891 bps |
| Basechain seqno | 85 | 1,212 | 1,127 | 451 s | 2.498891 bps |

The 451-second measurement initially inherited the development profile's longer
ConfigParam 28 lifetimes. After correcting the profile to the production
250/250/1,000-second values, a fresh four-process network produced:

| Measurement | Start | End | Delta | Elapsed | Finalized rate |
|---|---:|---:|---:|---:|---:|
| Masterchain seqno | 59 | 435 | 376 | 151 s | 2.490066 bps |
| Basechain seqno | 58 | 433 | 375 | 151 s | 2.483444 bps |

The longer run was within 0.045% of the configured 2.5 blocks per second, and
the production-lifetime confirmation was within 0.67%. For integer-nanotomi
calibration, this report uses the configured and observed steady-state rate of
2.5 bps for both chains.

A separate one-offline-validator run used three active processes with the same
four-member genesis set:

| Measurement | Start | End | Delta | Elapsed | Finalized rate |
|---|---:|---:|---:|---:|---:|
| Masterchain seqno | 529 | 1,459 | 930 | 451 s | 2.062084 bps |
| Basechain seqno | 528 | 1,459 | 931 | 451 s | 2.064302 bps |

The lower wall-clock issuance rate in the fault-tolerance run is expected:
missing-validator leader windows reduce production, and the design creates no
reward debt or later catch-up.

## Candidate reward calculation

The planning target after the provisional 101,000-TOS genesis is:

```text
target post-genesis creation = 4,999,899,000 TOS
reference interval           = 2,557 days
target creation rate         = 22.6316782905 TOS/s
```

The existing masterchain-to-basechain reward ratio of 1.7:1 is retained. With
one masterchain and one unsplit basechain shard both producing 2.5 bps:

```text
2.5 * (R_mc + R_bc) = 22.6316782905
R_mc / R_bc         = 1.7
```

Rounded to one nanotomi:

```text
ConfigParam 14 masterchain value = 5.699830088 TOS
ConfigParam 14 basechain value   = 3.352841228 TOS
```

The resulting reference rate is 22.631678290 TOS/s. Over exactly 2,557 days,
it creates 4,999,898,999.882592 TOS, only 0.117408 TOS below the planning
target.

## Reference projections

These are arithmetic projections under continuous 2.5/2.5 bps production, not
promises:

| Elapsed from reference start | Days | Projected post-genesis creation |
|---|---:|---:|
| 1 year | 365 | 713,712,606.553440 TOS |
| 3 years | 1,096 | 2,143,093,196.664576 TOS |
| 5 years | 1,826 | 3,570,518,409.771456 TOS |
| 7 years | 2,557 | 4,999,898,999.882592 TOS |

At the measured three-process fault-tolerance rate, creation per wall-clock
second is lower. Outages, validator availability, shard behavior, workload,
software changes, and governance activation timing will make actual results
differ.

## Collector-path observation

Before candidate values were installed, the same network used the legacy
1.7-TOS masterchain and 1-TOS basechain test values. At masterchain seqno 1,093
and basechain seqno 1,092, the Elector balance was exactly:

```text
500 + 1,093 * 1.7 + 1,092 * 1 = 3,450.1 TOS
```

This proves the existing ConfigParam 3-absent collector fallback delivered
every observed native creation amount to the Elector without loss or
duplication. It does not by itself prove post-election proportional bonus
recovery; the two-overlapping-election launch gate remains open.

## Required follow-up

Before production genesis:

1. Repeat the measurement across independent hosts, networks, and operators
   for a materially longer interval and under non-empty workload.
2. Test validator downtime distributions rather than only all-online and
   one-offline endpoints.
3. Exercise shard split and merge behavior and verify depth-adjusted aggregate
   creation.
4. Complete two overlapping ordinary elections and recover both stake and
   proportional bonuses.
5. Demonstrate governance reduction and zeroing of both ConfigParam 14 values.
6. Recompute projections from the final binary, final zerostate parameters,
   and sustained measurements before freezing production hashes.
