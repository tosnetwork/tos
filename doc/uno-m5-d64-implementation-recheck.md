# Independent review of the D64 implementation

Reviewed commit: 5f628635d6afebbc11e9ccec8065ec1691c4e850, not an unspecified
current branch. This is B's after-the-fact implementation review, distinct
from the previous D64 algebra review. Source line numbers below are relative
to that pinned commit. Later D66 correction is explicitly separated below.
No A proof-test expected results were used to construct the dense matrix test.

## 2 and 3: derived points and checked monetary total

`uno/crypto/src/withdrawal_statement.rs`:

* Lines 14-18 define x, q, b and operation_fee as four separate u64 inputs.
* Lines 23-26 reject zero principal and use checked_add(x,q), then checked_add
  of b, mapping either overflow to UNO_CRYPTO_DECODE.
* Line 76 uses `amounts.total()?`; failure returns before public_opening at
  line 87, Scalar::from(total) at line 90 or either point construction.
* Lines 89-93 construct C_t=T*G+r*H and handle=r*P_A; the ten-point array uses
  the computed commitment at index 6 and the computed handle at indices 7,8.
* The only point inputs are six balance/auxiliary points (lines 63,72-74).
  There is no transfer-commitment or transfer-handle parameter, conditional
  fallback, deserializer or setter in this implementation. Stored fields are
  private (64-69); accessors return immutable references (106-109).
* Verification uses those stored points at lines 113-114. The proof's Sigma
  commitments are separate inputs; they do not replace the statement points.

Result: the constructor enforces these two properties for its own output.
This does NOT establish an actual verifier-side wire path: the commit explicitly
has no C ABI or host caller for this constructor (lines 3-5). Generic SEND
verification still exists and accepts generic SEND statements; a future host
must actually use the Withdrawal constructor for Withdrawal. A caller bypassing
it is outside this constructor's enforcement, not a hidden fallback inside it.
Authentication and independent checks of x/q/b against actual payout/configuration
are likewise host obligations, not established by adding three u64 parameters.

## 1: every coefficient, target and range object

Point slots used by both paths:

    p0=P_A, p1=P_B, p2=C_A, p3=D_A, p4=C'_A, p5=D'_A,
    p6=C_t, p7=D_tA, p8=D_tB, p9=J

Witness columns (zero based): w0=s_A, w1=new balance, w2=v, w3=r,
w4=rho, w5=t. Let O be the identity point, G/H the Pedersen generators.
Both ordinary SEND and Withdrawal use the following SAME dense matrix:

| Row / relation.rs line | w0 | w1 | w2 | w3 | w4 | w5 | Right-hand target |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 / 94 | p0 | O | O | O | O | O | H |
| 2 / 96 | p3 | G | G | O | O | O | p2-fG |
| 3 / 97 | O | G | G | O | O | H | p9-fG |
| 4 / 98 | O | G | O | O | H | O | p4 |
| 5 / 99 | O | O | O | O | p0 | O | p5 |
| 6 / 100 | O | O | G | H | O | O | p6 |
| 7 / 101 | O | O | O | p0 | O | O | p7 |
| 8 / 102 | O | O | O | p1 | O | O | p8 |

In particular, rows 6,7,8 share w3, not three independently indexed openings.
`check_sigma` lines 191-194 uses the same response vector against every row.
The six ordered range commitments at line 103 are exactly:

    p9; Bmax*G-p9; p4; Bmax*G-p4; p6-G; Vmax*G-p6

They are not removed when v is publicly pinned. Lines 19-25 and 131-134 pad
these six to eight with two identity commitments for the aggregate proof;
those are padding, not two new value constraints.

Why this is stronger than comparing counts: the new constructor calls the
ordinary SEND prepare branch at withdrawal_statement.rs:102 and its verify
method calls the ordinary SEND verifier at :113. There is no separate Withdrawal
matrix branch. The entire relation.rs blob before/after 5f628635d is identical:
`929e750c6c8e348000b701949d4dcbdb68f7ce23`. Specializing p1=p0 changes input
values and creates redundancy, not coefficients or witness indexing rules.
The context/opening domains intentionally differ; unchanged matrix does not
mean byte-identical challenges or operation semantics.

## 4: f separation established; authenticated tariff origin NOT established

Lines 98-101 append all four amounts separately to context. Line 102 passes
only amounts.operation_fee as relation fee; line 103 stores that same value;
line 113 verifies with it. x/q/b are not added into f on any constructor path.
`relation.rs:76,95-97,138` uses that public fee in the equations and transcript.

However, operation_fee is caller supplied. This module has no authenticated
fee-table lookup or equality comparison against a reconstructed tariff. The
only constructor callers found at this commit are prover tests
(`uno/prover/src/tests/withdrawal.rs:30,56`); no host caller exists. B's independent
constructor test changes operation_fee from one explicit test value to another:
both constructs succeed, fee() changes and context changes, while the derived
three points do not. This is binding/separation evidence, NOT fee authorization
or proof acceptance. No conclusion that f really came from a tariff table or
that D32's real fee ledger is correct follows from this commit.

## 5: P_B=P_A is enforced inside the constructor

The caller has only one owner-key input, balance_points[0]. Lines 92-93 copy
that very same byte array into p0 and p1. There is no P_B argument that another
caller can vary; getters do not permit replacing either slot. The ordinary SEND
branch rejects identity p0/p1 (relation.rs:91-93); public_opening already rejects
invalid/nonidentity owner encoding at withdrawal_statement.rs:35-36. This is
an enforced specialization, not merely a convention in A's test caller.
It does not constrain callers that bypass this type and invoke generic SEND.

## 6: opening domain and zero handling

Withdrawal line 37 uses exactly `uno-v2/withdrawal-opening`; lines 38-44 absorb
protocol-domain, withdrawal-id, attempt-id, owner-P and little-endian total,
then request 64 bytes labelled r. Lines 49-51 use from_bytes_mod_order_wide and
return UNO_CRYPTO_DECODE for zero; there is no loop, retry or resampling path.
Deposit's system_encryption.rs:14 instead uses `uno-v2/system-encryption`.
The strings are different; this is domain separation, not a claim that scalar
outputs can never coincide. A zero-wide-input unit test exists at lines 58-59;
this review's new tests do not claim independent execution of that private
zero-input branch. The cited implementation directly returns its error.

## Original-commit difference from later D66

At the requested original commit, withdrawal_statement.rs:77-79 ALSO rejects
T>limits.max_value before constructing a statement. That is an extra public
range gate, contrary to the subsequently finalized D66 rule reserving this
bound to the existing proof. It is not a changed matrix or unchecked overflow.
Commit 15c34b2052d46f01e6e976fb7957bbca2423ef03 removes precisely that gate;
the correction is already an ancestor of B's current tree. Do not report the
original commit as containing the later correction, or the historical difference
as a newly discovered current regression. No code was changed for this review.

## Directly executed independent checks and controls

```
python3 crypto/test/workchain-d64-independent-review.py \
  --repo /home/tomi/tos-m2 --target-dir /home/tomi/tos-m2/uno/crypto/target
```

The runner exports the pinned crypto crate to an isolated directory and adds B's
own test module, kept in `crypto/test/workchain-d64-independent-review.rs`.
It compares every row/column, every target, the six ranges and two padding
objects against an independently transcribed expectation. It also checks both
u64 overflow positions, fee/total separation, owner duplication and calculated
point placement. It does not construct proofs or run a Native node.

Observed: baseline 2/2 passed (exit 0); isolated row-6 witness index 2->1 mutation
failed the designated matrix test (exit 101); isolated range p6-G->p4-G mutation
failed that test (exit 101); restored run 2/2 passed (exit 0). No repository
production source or A-owned file was mutated. The runner preserves none of
its mutated source in the shared worktree; it is an explicit review tool, not
a default CTest gate or permanent lexical guarantee.

Conclusion: matrix/derived-point construction, checked total ordering, enforced
owner duplication and domain/zero handling are accounted for in the cited
implementation. Tariff authentication, actual Withdrawal wire dispatch and
physical payout-to-statement linkage cannot be established from this partial
commit. The original extra range gate is separately identified and already fixed
later. This review establishes implementation correspondence and bounded test
observations, not proof-system soundness or a completed D34 external review.
