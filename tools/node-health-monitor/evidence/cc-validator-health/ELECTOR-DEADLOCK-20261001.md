# Elector deadlock behind `key_block_stale` and `state_gc_lag` (2026-10-01)

## What the monitor saw

From 07:35 UTC every node raised `key_block_stale` and `state_gc_lag`. Both were
true: the chain kept producing blocks, but no key block followed block 83 700,
and state garbage collection cannot pass the last key block.

## What the chain was doing

Election `1790840137` closed at `1790840077` with `total_stake = 0`,
`failed = false`, `finished = false`. The local election driver had died at
07:24 on an HTTP 500 during a validator rollout, and its unit had
`Restart=no`, so nobody staked into that window.

From then on the elector could not make progress:

- `conduct_elections` postponed the closed election on every tick, because its
  effective stake was below `min_total_stake`.
- `process_pq_stake` refused every stake after `elect_close`, with reason 0,
  so the stake that postponement waited for could never arrive.
- The current validator set (param 34) expired at 07:35:37 and param 36 stayed
  empty. No configuration change meant no key block, and no key block meant GC
  stopped behind block 83 700.

The configuration contract has no external path that could have intervened.
Its `recv_external` throws.

## What changed since August

The elector was unchanged from the April rebrand (`40a0aa4c9`) through August.
All fifteen later changes landed on 2026-09-19 and 2026-09-20 in the
post-quantum cutover.

In the inherited elector, postponing was safe. A stake was accepted until the
election was `finished`, even after `elect_close`, and each new stake reset
`failed`. That is the meaning of the inherited comment "do not retry failed
elections until new stakes arrive": an under-staked election waited, and late
stake rescued it.

Two changes on 2026-09-19 removed that rescue and kept the waiting:

- **`6255c3a14` (stake boundary).** The post-quantum stake path started refusing
  from `elect_close`, so membership is fixed at the election's boundary rather
  than at whichever tick conducts it. The rule itself is sound. But it removed
  the only input that could end a postponement, and `conduct_elections` was not
  changed to match.
- **`d305b914d` (effective stake).** Readiness started to count only stake
  under controller profiles the configuration still admits, and an absent
  policy postpones too. That added two more ways into the same postponement.

After both changes, an election that closed short was permanent.

## Why no test caught it

- **The tests check each rule where it lives.** The boundary commit added
  `a_stake_after_the_election_closes_is_returned_before_the_tick_conducts_it`,
  which proves the refusal. No test asked what then happens to an election that
  closed short.
- **No test advanced time past `elect_at` for a closed election.** Every
  election test ticks at `elect_close` and looks at that one tick.
  `a_retired_profile_cannot_make_an_election_look_ready` even asserts that the
  election is "postponed, not failed". It covers recovery by re-admitting a
  profile, which needs no stake, so it protected the postponement without
  noticing that the stake-based recovery was gone.
- **Mutation testing cannot see a missing behaviour.** The contract guard
  suite removes each guard and requires a test to fail. That finds guards
  nothing holds. It cannot find a state with no way out.
- **Nothing exercised operator absence.** No CI job boots a chain. On the local
  network the driver always staked in time, until the first time it did not.

## Test perspectives that were missing

1. **Liveness.** From any reachable elector state, within bounded time, either
   a set is installed or a fresh election opens.
2. **Time progression across every boundary.** Each outcome (empty, below the
   minimum, failed selection, success) is followed across `elect_close`,
   `elect_at` and the current set's `utime_until`, not checked at one tick.
3. **Paired assumptions.** When a change closes an input, as the stake boundary
   did, test the states that relied on that input to recover.
4. **Money conservation through every exit.** On any path that ends an
   election, each stake comes back exactly once, to the account that put it up.
5. **Operator-absence fault injection.** On the development network, stop the
   election driver for a whole window and require the chain to recover.

## The fix (`982086887`)

A closed election that cannot be conducted is still postponed while the set it
would replace is in office, so re-admitting a retired profile can still revive
it. From `elect_at` it is cancelled. Every member's stake is credited to its
owner, the record is dropped, and the next tick announces a fresh election with
a full window. A failed selection no longer keeps the credits it paid to
retired-profile members, so cancellation refunds each stake exactly once.

The election driver unit now has `Restart=on-failure` with a 30 s delay.

## Evidence

Sandbox suite `elector_sandbox`, run against the native build of this branch:

| Elector | Result |
|---|---|
| Fixed | 78 passed, 0 failed |
| Previous (`5def57046`) | 75 passed; the three new tests fail |
| Fixed, but cancellation keeps the selection's credits | 77 passed; the exactly-once test fails ("money left a standing election") |

`test/pq-native/contract-guard-mutations.py` still kills every mutant.

Live drill on the rebuilt development network (zerostate root `de50a311…`,
elector code hash `3477aea8…`, equal to the compiled fixed elector):

| Time (UTC) | Event |
|---|---|
| 13:00 | Election driver stopped |
| 13:03–13:07 | Election `1790860068` open, then closed, with `total_stake = 0` |
| 13:07:53 | Election `1790860068` given up; election `1790860368` open, closing at `1790860308` |
| 13:08 | Driver restarted; stakes from nodes 1, 2, 3 and 7 accepted |
| 13:12 | Set elected in `1790860368` observed in office (`since 1790860368`) |

After the rebuild, no node has an active incident, and the doctor reports
17 pass, 0 fail, 3 not run.
