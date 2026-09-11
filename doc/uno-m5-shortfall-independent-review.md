# Independent positive-shortfall review

Reviewed A commit `82b53c675a9a2abc731637aa6665b7ec131d38a7`, not a moving tree.
This is retrospective independent inspection/decoding and isolated helper
execution after seeing A's report, not a new pre-observation prediction.
B changed no A source. Full Failed contract remains incomplete (including subsidy,
wrap/debt publication mutations and their oracle controls).

## 1. Operating income versus subsidy: a real limitation remains

The actual Failed engine branch (`crypto/test/workchain-m3-node-engine.h:363-381`)
constructs three account updates and `result.fees=accepted.fees`, without adding
explicit internal transfers. The helper (`crypto/block/workchain-failed-funded.h:
119-128`) supplies receipt y+b-s-g and fee components `{s,g,0}`. There is **no
standalone "reject operator subsidy" branch to remove here**. No coordinator
balance is available to the pure helper as spendable funding; general Native
allocation can execute internal transfers if an engine actually supplies them.
Thus absence of a subsidy edge in this particular branch is structural evidence,
not the requested live subsidy-mutant red. An engine adding a valid funding edge
is precisely the still-required integration mutation; deleting a comment or an
unrelated guard is not an honest substitute.

B independently decoded the accepted native effects: explicit transfer dictionary
empty. Coordinator balance 21,003,000,250 -> 21,006,000,250 (+3,000,000).
`workchain-native-allocation.h` fee branch credits only S to coordinator and debits
custody by S. These source/destination facts corroborate legitimate slot income;
net income alone would not exclude simultaneous subsidy plus another receipt.

A's live oracle `test/m5-live-failed.h:71-86` compares coordinator balance to old+s
and actual custody transaction fee to g. Its `correct_routing` predicate observes
real accepted state, but deleting that oracle does not create a subsidy path.
No independent publication mutant supplying an operator subsidy was executed in
this review. This part of item 12 is **not yet behaviorally certified**.

The actual extra helper guard at lines 95-96 checks zero reserve remainder and
amount<x on shortfall; it is NOT a subsidy check. B removed only that condition
in a shadow header: the same shortfall and four parameter variants still passed.
That result is expected: with checked cost=(x-y)+h>b and amount=y+b-h, amount<x;
min(cost,b) already forces remainder zero. This guard is redundant under the
preceding arithmetic. Do not count its presence as independent source-of-funds
protection, or its removal experiment as a subsidy experiment.

## 2. g has an actual fee destination

Independent artifact readings from `/tmp/uno-m3-live-6igzl00b`:

| Component | Actual observation |
| --- | --- |
| authenticated fee inputs | base=2, issuance billing units=4, slot=3,000,000 |
| custody transaction total_fees | 8 |
| block ValueFlow fees_collected | 2,629 |
| real wc0 bounce phase | 1,309 collected + 2,621 forwarded = 3,930 |
| Failed host fee components | S=3,000,000, C=8; no explicit transfer |

The block total reconciles as 8+2,621; it is not merely an absent coordinator
credit. Source path: `workchain-failed-funded.h:126` materializes `{s,compute,0}`;
`workchain-fee-settlement.h:35-37` sums C+T into collected;
`transaction.cpp:4937-4948` subtracts it from custody's allocated balance and
adds it to disposal_fees, then lines 4962-4963 install transaction fees.
`validator/impl/collator.cpp:6423-6446` aggregates transaction and import fees
into block fees_collected. B decoded both actual transaction and block fields.

Four helper runs with the same authenticated predecessor and real crypto backend
produced g/receipt: 8/7,996,062; base=3 ->12/7,996,058; units=5 ->10/7,996,060;
slot+1 ->8/7,996,061. Parameter changes here are resolved helper input controls,
not newly validated configuration-change blocks. Explicit units=4 is not frozen.

## 3. No persisted shortage claim in this path

`workchain-failed-funded.h:121-125` adds the backed system receipt, erases the
matched Withdrawal, advances the sequence and re-encodes the accounts. Independent
complete account decoder sees one old Withdrawal, zero new Withdrawals and one
origin receipt. The commit changes neither `block.tlb` nor the Withdrawal codec;
the existing costs fields are not supplemented with shortage/debt fields.
`test/m5-live-failed.h:97-102` computes shortage locally with checked currency
subtraction solely to print an event. The helper's consumed/remainder locals are
not serialized as a new terminal obligation.

This is schema/source inspection plus actual terminal account observation. It is
not a mutation proving rejection of an engine that invents a different debt
representation. That item remains in the mandatory shortfall contract.

## 4. Positive shortfall and checked arithmetic

Decoded principal x=10,000,000, actual bounce y=9,996,070, original reserve
b=1,000,000 (from authenticated prepare, not an edited authorized record).
Cost=(x-y)+s+g=3,003,938>b; gross=y+b=10,996,070;
installed receipt z=gross-s-g=7,996,062<x. Event shortfall x-z=2,003,938.
Actual custody increases 6,996,062 to 996,995,705; W record removed.

Lines 79-86 use checked x-y, multiplication, both fee/cost additions, y+b,
gross-fee and x+b. Lines 91-94 bound consumption by min(cost,b) before checked
b-consumed. There is **no raw x-(y+topup) expression**. Live reporting first
checks amount<x and uses checked CurrencyCollection::sub(principal,amount).
Do not subtract the entire cost from b; here b-cost would be negative, but that
expression is never used. Overcompensation in a funded case is not confused with
shortfall's positive x-z.

B's extra helper controls use the same real association and deliberately select:
base=UINT64_MAX (compute multiplication overflow), slot=UINT64_MAX (fee addition
overflow), and fee=10,996,071>gross (subtraction underflow). All return the exact
helper arithmetic/no-issuance error, before receipt success. These establish
those bounded helper refusals, not all possible u64 inputs or a live wrap mutant.
The legitimate no-issuance branch remains unsupported here and separately owed;
its rejection is not claimed as correct protocol behavior.

## Experiments and limits

Fresh isolated translation units against the pinned helper and existing Native
libraries, real system-encryption backend:

- normal: pass; redundant shortfall-bound guard removed: pass;
- restore only the old cost>b rejection: exit 1 at `probe.cpp:60`,
  `outcome.is_ok()` (real association reaches the helper and legitimate shortfall
  is rejected). No proof-format/admission error supplied that red;
- restored original: pass; additional actual-artifact/overflow controls: pass.

Evidence in `measurements/uno-m5-shortfall-independent/` records input hashes,
source, commands and logs. Other linked dependencies and B's compatible codecs
were reused, not a full clean rebuild. Artifacts were generated/accepted by A;
B independently decoded them and executed the helper, but did not rerun the live
chain or independently re-decrypt the receipt in this review. Its amount field
and balances were independently read; A's test-key decryption remains A's evidence.

Conclusion: the implemented positive-shortfall arithmetic, observed fee destination
and absence of persisted shortage are supported at these stated cuts. The missing
subsidy publication mutation is still missing. No full item-12 completion, guard
retirement, no-issuance support, or exhaustive no-subsidy guarantee is asserted.
