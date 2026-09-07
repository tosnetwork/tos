# Native outbound queue construction for multi-account batches

`crypto/block/workchain-outbound-queues.h` builds actual OutMsgDescr,
OutMsgQueue and DispatchQueue dictionary roots from the reconstructed outputs
of the full write-set overlay. It is an enqueue-only, post-admission helper,
not a production collator/validator activation or a new message delivery rule.

## Native rules retained

- Outputs are processed in Native logical-time/message-hash order. Equal LTs
  do not collide in the ordinary queue, whose key includes the message hash.
- Mandatory deferral depends on the **actual message source**: either its
  current DispatchQueue exists or earlier dispatch messages remain unprocessed
  in the host pass. Processing-account identity is not a substitute.
- Optional deferral remains an explicit Native choice. Without a source
  backlog, deferral must be enabled and transaction message index zero cannot
  be deferred. A backlog still requires deferral when optional deferral is off.
- Metadata binds the **processing transaction account** and its start LT, not
  the foreign source carried by a reconstructed bounce.
- Normal envelopes use existing hypercube routing. Deferred envelopes use
  current/next address zero. Records retain the actual transaction reference.
- The ordinary queue uses the existing envelope-to-key function. DispatchQueue
  uses actual source / message LT, and checked increments must fit its uint48
  count. All result counters are checked. The successfully decoded uint15
  transaction count bounds the message index before narrowing.

No new TL-B, numeric policy defaults, or voting error categories are introduced.
The helper validates tuple membership, timestamps, LT, metadata and deferral;
it does not authorize a source/processing-account exception. Full independent
transaction reconstruction and the versioned exception remain host duties.

## State ownership and evidence scope

Inputs are the current private Native queue snapshots, after earlier block
processing, plus the unprocessed-dispatch source set from that same pass. They
must not be replaced by previous-block roots or inferred from the output list.
Admission must cover all referenced closures; entry limits are not Cell budgets.
Exceptions propagate with source provenance. Errors are not by themselves a
classification of candidate invalidity versus local unavailability.

All dictionary changes are private until success. Duplicate records and late
failures cannot publish partially updated queue roots. Returned queue counts
are deltas for this output set, not claimed totals for existing queues.

The joint payout/disposal fixture exercises three ordinary exports (Native
augmentation 712 nanotomi), one ordinary plus two deferred exports, source
backlogs in both current queues and the unprocessed set, optional deferral,
metadata, duplicate insertion, output bounds and mismatched LT. The two bounce
messages are stored under their foreign source rather than the coordinator.
Manual rebuilt removal evidence is recorded in
`measurements/uno-v2-outbound-queues-evidence.json`; it is not recurring mutation
CI. The fixture uses real Native dictionaries and codecs, not a live validator.
Standalone compilation exposed a missing explicit codec include, now fixed.
The new header is first in the recurring test translation unit so that later
includes cannot conceal this dependency failure again.

## Still required for M1

Live collation must supply the correct intermediate queues and Native deferral
choices, preserve block resource accounting and publish once. Live validation
must reconstruct the participant set and apply the versioned source exceptions
at both Native checks. Its per-transaction deferral state must not be reused
unchanged for coordinator messages with multiple actual sources. Production
dispatched-message processing and backlog recovery remain required evidence.

The helper-only unit awaits M1 milestone review. M1 is not complete.
