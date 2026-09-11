# D69 independent host review

Specification SHA-256 prefix `89b34a01128fbf18`; checked locally. This review
does not read B's accounting predictions or claim installed M5 settlement.

Compatibility clarification checked against specification `1fd13648aa54a65f`:
retain Deposit's exact D33 transcript and existing vectors. New origin members
use distinct transcript labels, not an added kind byte in the old Deposit
transcript. Failed and late return enter through custody, not the coordinator's
Deposit entry; retain the latter's bounced-message rejection. These corrections
agree with the representation/dispatch distinction documented below.

## Sources and representation

The current `uno_v2_system_pending_receipt` requires
`origin:^UnoV2DepositIdentity`; that identity requires an inbound Message hash
and sequence. Paid's window-closing event and type-two bucket sweep have no
inbound Message at issuance. Their current unrepresentability is confirmed.

The five listed event categories cover the presently specified issuance paths:
Deposit, in-window Failed, late return, Paid reserve return and type-two sweep.
SEND creates user receipts, COLLECT consumes receipts, and registration/closure
do not create system receipts. The D65 small-remainder branch creates no receipt.
If Failed produces separate principal/reserve receipts, each actual issuance
must consume a sequence; that is not a new origin category.

## Failed message identity: available representation, missing route

`WorkchainNativeInboxPlan` retains complete envelopes. Final-import evidence
uses `envelope.msg->get_hash().bits()` as the dictionary key with Add semantics
(`workchain-import-evidence.h`). The current Deposit host already passes this
exact Message representation hash to its transition, not envelope/body/BoC
hash. Thus the authenticated bounce Message can supply an inbound identity;
do not substitute `original_info.created_lt` or the original payout hash.

However, the current Deposit branch in `workchain-m3-node-engine.h` explicitly
rejects `info.bounced`. Failed settlement is not installed. Reusing Deposit
admission unchanged would reject that bounce. A dedicated authenticated Failed
dispatch must retain the envelope and validate Attempt linkage before issuance.
This is code-level availability, not live evidence that Failed already does it.

## Shared sequence installation

`next_workchain_deposit_sequence` rejects UINT64_MAX before incrementing.
Deposit admission calculates the prospective next value and checks the derived
ID against both pending kinds. The transition installs that value in a copied
coordinator state together with the new receipt; post-metering failures return
no successful transition. The node returns both updates in the same effects.

Generalizing origins does not invalidate checked increment arithmetic, but it
does not automatically supply transaction ordering. All successful issuances
must advance the same staged authenticated coordinator counter, including
multiple sources in one batch. Independent builders must not each read the
same old counter and publish competing next values. Failure/no-entry paths
must not publish an increment. These new-path behavioral controls remain to
be implemented; current Deposit success is not evidence for all three origins.

## Rationale correction requested

The statement that two equal reserve returns to one account necessarily yield
the same r without a sequence is too strong for the proposed transcript:
Withdrawal settlement also absorbs Attempt ID. Different Withdrawal identities
produce distinct Attempt identity preimages, so equal owner/amount alone does
not establish identical transcript inputs, much less identical outputs.

This does not oppose mandatory shared sequencing. A checked counter supplies
stateful issuance ordering; it is not a proof that a finite hash/scalar output
cannot collide. Preserve authenticated duplicate-ID checks across both pending
kinds. Domain separation, replay prevention and hash collision handling are
distinct properties. No sequence or collision check was removed by this review.
