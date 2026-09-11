# M4 fee prediction before the new observation

## Status and independence

This document commits a prediction for the coordinator-supplied input below
before A is asked to execute that input. No result for this input has been
received. The earlier observations, SEND 4581 and COLLECT 5285, were already
received and are not predictions; they are handled separately below.

Independence is behavioral, not structural: A's fee implementation is present
in the same worktree. The derivation does not read its calculation functions,
validator reconstruction, or test expectations. Code inspection was limited to
the authenticated configuration field declarations and their source comments.
The basis is D25/D28/D32 in `/home/tomi/memo/TOS_UNO_PRIVACY_WORKCHAIN_V2.md`,
sections 9.2 and 12, plus the coordinator's explicit test inputs. This does not
claim that these test prices are approved deployment parameters.

## Explicit input

All monetary values are integer nanotomi. Use one SEND and one COLLECT, also
reported individually. COLLECT may select any valid nonempty set up to its
authenticated capacity; its billing weight does not depend on that count.

| Authenticated input | Value |
|---|---:|
| base | 1000 |
| slot_fee | 250 |
| send_tip | 7 |
| collect_tip | 11 |

## Derivation

1. D25 / section 12.1 assigns SEND's state component to `pending_slot_fee` and
   COLLECT's state component to zero. Therefore SEND S = 250 and COLLECT S = 0.
2. D28 / section 12 assigns SEND one billing unit and COLLECT three, for any
   valid k. These billing units are not cryptographic proof-work units.
   Therefore SEND C = 1000 * 1 = 1000 and COLLECT C = 1000 * 3 = 3000.
3. The supplied static tariff gives SEND T = 7 and COLLECT T = 11. Neither is
   inferred from aggregate fees, proof work, or a local default.
4. D32 / section 9.2 requires F = S + C + T. Thus SEND F = 250 + 1000 + 7 =
   1257; COLLECT F = 0 + 3000 + 11 = 3011.
5. D32 directs S to the authenticated coordinator's operating budget through
   a same-shard internal allocation, and C + T to this block's fees_collected.
   Neither route emits a custody fee message. C + T belongs to the existing
   validator fee pool, not a caller-chosen recipient or the block creator alone.
6. The same atomic fee operation reduces custody and N_book by the same F.
   Registering an account, crediting Deposit principal, and paying external
   Native processing costs are not included in these two operation rows.

## Committed expected values

| Operation | S | C | T | F | Coordinator operating credit (S) | fees_collected increment (C+T) | Custody fee delta | N_book fee delta |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| One SEND | 250 | 1000 | 7 | 1257 | +250 | +1007 | -1257 | -1257 |
| One COLLECT | 0 | 3000 | 11 | 3011 | 0 | +3011 | -3011 | -3011 |
| Both in one successful batch | 250 | 4000 | 18 | 4268 | +250 | +4018 | -4268 | -4268 |

These are increments attributable to these operations, not the entire block's
fee total or final account balances. Other authorized block costs, if present,
must be reported separately. For the combined row, the conservation check is
250 + 4018 = 4268, and the paired backing/liability reduction is 4268 each.
Matching F alone is insufficient: S, C, T, destinations, and both reductions
must match independently. No execution success is claimed by this prediction.

## Separate retrospective comparison

A previously reported C + T values of 4581 for SEND and 5285 for COLLECT.
Their original authenticated tariff inputs have not been supplied to B.
Consequently, no agreement or disagreement is concluded here. Any later
comparison using those inputs must be labeled **retrospective check, not a
prediction** and must not be presented as evidence for the timing of the new
prediction above.

## Process correction

The earlier instruction required writing the expectation before looking at
results, but did not require committing it. The expectation appeared only in
conversation, without a committed artifact. For independent predictive checks,
require **commit before observation**, not merely write before observation.
This document preserves that distinction; it does not upgrade the earlier
4581/5285 comparison into a prediction.
