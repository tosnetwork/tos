# ADR-0002: Pooled stake belongs below the protocol, and stays dark until it can pay

## Status

Accepted (2026-08-18)

## Context

TOS carries a multi-nominator staking pool contract
(`crypto/smartcont/nominator-pool/pool.fc`), ported from upstream and adapted
for TOS units. Until recently nothing in the tree could operate it: the
elections daemon refused the one pool kind that holds other people's money, the
bytecode was reproducible but unenforced, the punishment parameter the pool
reads to size a validator's own funds was absent from genesis, and no run had
ever taken a pool through a staking round.

That work is now done and verified against a real chain. A pool deploys at the
address its parameters derive, basechain depositors join with a one-letter
comment, the Elector accepts a stake sent by the pool, the stake and its
rewards come back, the split is exact, and a depositor can leave — including
when the validator stops answering entirely.

Two facts about the surrounding system did not change, and they decide what
this contract is allowed to become.

**The protocol does not know that depositors exist.** The Elector settles with
whichever masterchain address staked. `doc/tos-validator-only-token-economics.md`
describes rewards as payments to elected validators throughout, and the roadmap
has no pooled-staking entry. A pool is an arrangement *between* a validator and
its depositors that the chain neither models nor enforces: nothing on chain
records what a depositor put in, and a withdrawal erases their ledger entry
outright.

**Pooled capital currently earns nothing at the margin.** ConfigParam 17's
`max_stake_factor` is 1, so the Elector caps every elected validator's effective
stake at the smallest stake in the set and refunds the surplus. A pool holding
ten times the minimum is paid exactly what a solo validator holding the minimum
is paid. Raising the factor is a governance act with a hard prerequisite —
`factor < (min_validators - 1) / 2`, so a factor of three needs at least eight
validators — and the floor has to move before the factor does.

## Decision

**Pooled stake is an application-layer arrangement, not a protocol feature.**
The chain will not learn about depositors: no protocol-level nominator
accounting, no consensus rule that distinguishes a pooled stake from a solo
one, no reward path that pays anyone but the address that staked. What TOS
provides is what it already provides — an Elector that settles with a staking
address, and a permissionless way for anyone to advance a pool that its
validator has stopped tending.

**No user-facing entry point ships while the factor is one.** A wallet button
or an explorer call to action that invites a deposit today is inviting capital
into a position with zero expected marginal return and non-zero risk: slashing
exposure, a lockup measured in rounds, and dependence on a validator's conduct.
That is true regardless of how carefully the interface is worded, so the
interface is not the fix.

**Every surface that shows a pool must state the cap.** `/explorer/staking`
reports `max_stake_factor`, the smallest stake actually elected, the effective
ceiling the two imply, and `surplus_earns`. A page that renders a pool balance
beside a reward rate without them is describing a return that does not exist
for the next deposit.

**The order of the governance sequence is enforced in tooling, not prose.**
`scripts/propose-validator-count.sh` raises the floor and refuses a floor the
network cannot absorb an absence under; `scripts/propose-stake-factor.sh`
refuses to emit a signable proposal until the floor supports the factor. The
unsafe ordering — factor first — cannot be produced by the tools.

## Alternatives considered

**Make pooled stake a protocol feature.** The Elector could account for
depositors directly, removing the trust layer between them and the validator.
It would also put every depositor's balance in consensus-critical code, make
the reward path considerably harder to reason about, and commit the protocol to
a product decision it has so far declined. The contract-level arrangement keeps
the failure surface in a contract that can be replaced without a fork.

**Ship the wallet entry now with a warning.** Rejected on the grounds that a
warning does not change the arithmetic. If a deposit cannot earn, the honest
interface is its absence.

**Delete the pool contract and stop here.** Tempting while the factor is one,
and it would remove a trust layer the protocol never asked for. Rejected
because the work that makes a pool safe — the punishment schedule, the bytecode
lock, the permissionless recovery path — is the work that makes *any* staking
arrangement safe, and because the factor is expected to move once the validator
set is large enough to allow it. Removing the contract would mean rebuilding
this ground later under time pressure.

## Consequences

A pool is operable today and earns nothing today. That is a coherent state, not
a contradiction: the machinery is finished and waiting on a parameter, and the
parameter is waiting on validator count rather than on engineering.

Anyone who deposits before the factor rises does so knowingly, using tools
rather than a product surface, and the explorer will tell them their marginal
deposit does not earn. Anyone building a product surface has a single field to
gate on.

TOS carries an unused contract and its supporting tooling in the meantime. The
cost is a code lock to maintain and an end-to-end run to keep green. The
alternative was carrying the same cost later, at whatever moment the factor
changed, with depositors already waiting.

If the factor is not raised — if the validator set never reaches the size the
concentration limit requires — then this contract should be removed rather than
left in place as a permanent invitation to a position that cannot pay. That is
a decision to revisit, not one to defer indefinitely.

## References

- `crypto/smartcont/nominator-pool/pool.fc` — the contract; the depositor
  interface is the `op == 0` branch at line 371, the recovery guard at 566.
- `crypto/smartcont/elector-code.fc:772` — `true_stake = min(stake, max_f *
  m_stake >> 16)`, the cap this ADR turns on.
- `crypto/smartcont/gen-zerostate.fif` — ConfigParam 17 sets the factor to 1;
  ConfigParam 40 carries the punishment schedule the pool sizes against.
- `scripts/check-stake-factor-safety.py`, `scripts/propose-validator-count.sh`,
  `scripts/propose-stake-factor.sh` — the gated governance sequence.
- `scripts/nominator-pool-lifecycle-e2e.py` — the end-to-end run, including the
  leg that recovers and pays out a pool without the validator acting.
- `tosctl/src/node-control/service/src/http/explorer_query_api.rs` —
  `effective_stake` on `/explorer/staking`, and the per-depositor position
  endpoint.
- `doc/tos-validator-only-token-economics.md:349-363` — the concentration limit
  the factor bound is derived from.
