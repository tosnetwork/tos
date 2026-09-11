# Positive-issuance shortfall checkpoint

Contract source: B `f75612eaf`, merged as `16ebdbebf`, not copied. Its mandatory
twelfth item remains NOT_READY until all designated mutations and oracle
controls execute. The contract distinguishes legitimate slot income from a
prohibited operator-funded subsidy; this implementation does not change it.

## Narrow change

The registered Failed path now permits `cost > b` when the real issuance pot
`y+b` exceeds `slot+g`. The same checked pot subtraction computes the user's
receipt, with no new funding edge. Consumption is bounded by `min(cost,b)` before
subtracting it from b. Shortfall must leave zero reserve remainder and a positive
receipt smaller than x. The matching W record is removed; no residual shortage
claim or state field is added. Late/no-slot/no-issuance branches remain unsupported.

The Native allocation and fee-routing code is unchanged. The coordinator's
observed increment remains exactly the slot fee, not zero; actual custody
transaction fees remain g. A subsidy would be an operator-funded expense, even
if a legitimate slot receipt hid it in the net balance. Both attribution and
the actual published account/transaction values matter.

## Fixture and observations

The new test profile supplies b=1,000,000 in the authenticated genesis business
configuration BEFORE prepare, with x=10,000,000 and a newly matching proof.
It does not modify an authorized W record or bypass the D76 reserve anchor.
All numeric test policy choices remain explicit, not frozen production defaults.
The normal profile still supplies b=4,000,000.

Execution runs real prepare, payout delivery to wc0, real rich bounce, custody
association and validator replay. The observer decodes accepted Native accounts,
transaction fees, owner control/pending roots and sequence, decrypts the receipt
with test keys, and runs the existing backing replay. Reported shortfall is an
event-only derived value, not a persistent entitlement.

Before the implementation change the real node returned
`-7201: funded Failed transition unavailable in test profile`; the driver failed
at `FAILED_SHORTFALL_ACCEPTED` after the matched transition was attempted.
Log: `/tmp/uno-shortfall-red.log`. This is an acceptance failure, not evidence
that rejecting legitimate shortfall was correct. No earlier proof or reserve
admission failure substitutes for this red.

Default linked-Ninja CTest registration:
`test-workchain-withdrawal-failed-shortfall-positive-partial`.
It deliberately does not emit the full twelfth-contract marker. The complete
subsidy/wrapping/old-rejection/residual-debt mutations and per-oracle removals
remain outstanding, as does adjacent no-issuance coverage. No guard is retired;
the unrelated codec exception assertion is not changed. No claim of complete
classification follows from observed zero unknown counters.

## Executed checkpoint (2026-09-11)

The named partial CTest passed 1/1 (35.26 seconds). Actual values:
x=10,000,000; q=100; b=1,000,000; y=9,996,070; return loss=3,930;
slot=3,000,000; g=8. The receipt is 7,996,062, consumed reserve is 1,000,000,
remaining reserve is zero, and event-only shortage is 2,003,938.
Coordinator income is exactly the slot fee and actual custody transaction fees
are g. Sequence advances 1->2; P=W=0; both equation sides are 996,995,705
(R_actual=R_book=N_hidden), with D's structural zero explicitly retained.
Observed process-local unknown counters are zero, not classification completeness.

The original b=4,000,000 funded live sequence was rerun separately: receipt
10,996,062, unchanged terminal backing 996,995,705 and sequence 1->2.
Logs: `/tmp/uno-shortfall-ctest.log`,
`/tmp/uno-shortfall-funded-regression.log`. The readiness runner still exits 1
and lists all twelve missing complete slots; its self-tests pass 11/11.
