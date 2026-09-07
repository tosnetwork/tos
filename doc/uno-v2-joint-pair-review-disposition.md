# Joint payout/disposal preparation: boundary review disposition

This M1 unit extends the existing private payout pair with an explicit disposal
context. Custody still authorizes principal against its old balance. Imports
and committed allocations precede settlement; the coordinator retains its
disposal messages and fees while separately funding payout forwarding.
Nothing commits an Account or writes CellDb here. Full mixed-batch overlay and
queue publication remain unimplemented; this is not M1 acceptance.

The read-only boundary review ran NativeDisposalEntry and all 82 block tests.
Verbatim output is in `~/memo/reviews/uno-v2-joint-payout-disposal-review.txt`.

## Disposition

| Review item | Disposition |
|---|---|
| F1: divergent workchain tables | Fixed. The joint call requires both pricing and workchain-table reference identity. A table missing the bounce destination now fails rather than silently changing the disposal branch under inconsistent configuration. The removed check makes the new negative fail. Reference identity is local API consistency, not authentication. |
| Null entry context test gap | Fixed. A disposal context with both entry roots absent is rejected; removing that clause makes the call succeed and the test fail. |
| F2: accounting rows omit disposal | Documentation fixed. These are incremental payout-stage rows, whose starting balances are already post-import/allocation/disposal. They must not be read as complete transaction rows. The added test decodes actual serialized balances, fees, outgoing value and InMsg credits, then checks the complete two-account graph including the host fee edge. |
| F3: custody fee assignment | Mandatory extra guard disputed. This is assignment of the complete custody fee, not unchecked addition. The custody import participant has no transaction fee-producing phase; incoming forwarding fees live in InMsgDescr and disposal runs only on coordinator. The invariant is now explicit. An unreachable zero guard would not add an independently testable property. Any future custody fee-producing path requires revisiting this contract. |
| F4: no null-table check | Disputed. `Transaction::stage_workchain_messages` checks `!cfg.workchains` before staging or destination rewriting. A null-table test on the unchanged null-disposal path passes; removing that existing guard makes it fail. No duplicate guard added. |
| P1: incompatible output-limit meanings | The ambiguity is clarified at the field, without a new schema or number. `max_outbound` is batch-total. The inner disposal check is necessary but not sufficient when another emitter exists; the checked `bounce_count + 1` is the joint check. With only one emitter, the same total bound naturally permits all N outputs. This agrees with the existing participant LT planner's summed output budget; it is not two independent allowances. |
| P2: common LT implies one emitter | That inference is disputed. The planner supports per-participant counts with a common start; its existing payout caller passing 1 does not impose a structural one-emitter invariant. Native NewOutMsg ordering breaks LT ties by message hash; queue keys include message hash, while DispatchQueue is keyed by actual source then LT. Full Native queue/validation evidence with both emitters still remains required. No LT repartitioning or new scheduling schema is claimed here. |
| P3: third participant double credit | Disputed for the actual caller. Non-role participants in the payout overlay call `prepare_workchain_allocation_participant`, not the importing participant. The two Native entry roles are not the full write set. A message to another touched account remains misdirected and is processed by coordinator; that storage participant does not also import it. Follow-up mixed-overlay tests must retain this distinction, not restrict all batches to two accounts. |
| Error-string assertions | Not adopted as the evidence substitute. Each targeted guard is removed and rebuilt, and tests fail on result/state/count properties. Exact message text would not prove the guard is load-bearing. |

An absent workchain in a genuinely authenticated table can legitimately select
the protocol's no-route credit branch. F1 concerns divergent local configuration
sources, not converting that valid protocol predicate into a local failure.
The review's null-table concern must also not be confused with that predicate.

## Evidence and remaining scope

Eight rebuilt controls failed: replace joint disposal with strict entry, omit the
payout from the output count, remove custody binding, permit absent entry roots,
remove pricing identity, remove table identity, omit the serialized graph's fee
funding edge, and remove the pre-existing null-table protection. Restored
validator-engine compilation, the five registered regression tests (3.73 seconds)
and standalone transaction-header compilation passed. Raw output, edits and
hashes are in `measurements/uno-v2-joint-pair-evidence.json`. Manual removal runs
are not recurring mutation CI.

Fixture amounts are nanotomi, not production fee proposals: custody finishes at
1090, coordinator at 973; their collected fees are 25 and 100. The pair carries
one payout and two disposal bounces. Complete value-flow rows are reconstructed
from Native artifacts, not copied from incremental payout accounting.

Cash conservation does not authorize spending unexpected-credit liabilities.
The authenticated engine/host must derive the free operating fee budget and
maintain those liabilities; neither this primitive nor its returned accounting
rows certifies that authorization. Source-aware admission, final voting error
classification and containment of actual VM/builder/allocation exceptions remain
enclosing-host duties. No new catch-all or voting error category was introduced.
