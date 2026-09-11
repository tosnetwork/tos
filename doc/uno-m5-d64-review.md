# D64 review against the implemented SEND relation

Specification commit `061dd218`, SHA256
`1221faf1eaf3a7219c11497ce5ae72b460b3980554e3afcb506926dc4089661f`.
Production source baseline `fa7dd4a18` (no Withdrawal implementation).
This review does not change the relation or prescribe a new proof system.

The coordinator subsequently supplied specification `8f02a558` /
`38e340e2afe6fa8e`, correcting the single-handle deletion claim as A also
observed. The original-version citations below are retained as the reviewed
text; the redundancy conclusion agrees with that correction.

## Equations and witness sharing

`uno/crypto/src/relation.rs:100` builds equation six as
`w[2] G + w[3] H = p[6]`. Line 101 builds equation seven as
`w[3] p[0] = p[7]`. Line 102 uses the same `w[3]` for the recipient handle.
The witness order is `(s, a_after, v, r, rho, t)`. Lines 79-84 allocate one
column per witness. Lines 191-195 check every row against the **same** response
vector, rather than accepting a separate response for each equation.
The SEND shape is eight equations and six witnesses (line 29), with six real
range commitments padded to eight (lines 103,131-134).

The new `d64_shared_witness_and_equal_handles` test checks these exact matrix
slots and verifies a same-key SEND proof with the existing kernel. It is an
algebra fixture with an explicit test opening, not an implementation of the
Withdrawal opening transcript or an authenticated Withdrawal context.

## Group and nonidentity enforcement

The kernel imports `RistrettoPoint`, not unrestricted Edwards points
(`relation.rs:3-4`); every encoded point is decompressed as `CompressedRistretto`
(lines 15-16,69). SEND explicitly rejects identity at indices 0,1,5,7,8
(lines 91-93), including both public keys and both transfer handles.
The existing nonidentity test executes that check, before proof verification,
for SEND and COLLECT (`uno/crypto/src/tests.rs`, test
`nonidentity_handles_are_checked_before_proof_verification`).

Pinned curve revision `10042b03cfc92e505e9d33d2827d5c0f0d36989a`,
`curve25519-dalek/src/constants.rs:68-70`, gives the Ristretto order:

```
l = 2^252 + 27742317777372353535851937790883648493
  = 7237005577332262213973186563042994240857116359379907606001950938285454250989
```

The [Ristretto specification](https://ristretto.group/) describes the
prime-order group abstraction. This review checks use of that abstraction;
it is not an independent audit of the curve implementation.

## What is unconditional

Given a shared scalar witness satisfying the equations, nonidentity P_A and
the correctly rebuilt public points, `(r-r0) P_A = 0` forces `r=r0` in Z_l.
Then `(v-T) G=0` forces `v=T` in Z_l. With integer representatives in `[0,l)`,
the equality is exact. This algebraic implication needs no discrete-log
assumption relating G and H.

It does **not** turn proof acceptance into an unconditional guarantee. The
argument applies to a satisfying/extracted witness; acceptance-to-extraction
is the proof-system soundness premise. The implementation verifies response
equations and the Bulletproof, not an extracted witness. Fiat-Shamir derives
the challenge at lines 149-154; the range proof is checked at lines 178-182.
The precise claim is: **conditional on the existing proof system's soundness,
the additional public-opening algebra requires no new computational assumption**.
It must not be shortened to unconditional soundness of accepted Withdrawals.

## Amount bounds

Frozen `V_max = B_max = 2^62 - 1 = 4611686018427387903`.
The checked sum `T=x+q+b` must satisfy the SEND range bound as well as the
source's ability to pay `T+f`. Even when each component is individually valid,
their sum can exceed V_max. In particular, x=V_max and any positive q+b do so.
For source available amount a, the necessary arithmetic bound is
`x <= min(V_max, a-f) - q - b`, with every subtraction checked.

An admitted u64 sum is below l, so this is not a scalar-wrap issue. u64
addition overflow must be rejected **before** conversion to a scalar.
For a representable T above V_max, the retained `V_max-v` range object is
inconsistent with its required range under proof soundness. The ordinary
prover may reject an invalid range opening earlier; neither outcome should
be mislabeled a host admission test. No out-of-bound Withdrawal host execution
has been run in this review, and no limit is enlarged to accommodate it.

## Three points: reconstruction, verification, and redundancy

In the current SEND kernel all three supplied point slots are used, at lines
100-102, and all points enter the transcript at lines 142-143. There is no
conditional omission of a SEND row. The new test changes each of p[6], p[7],
p[8] independently: preparation still succeeds, verification returns
`UNO_CRYPTO_VERIFY = 3`, and restoration succeeds. This demonstrates binding
of the actual point slots, **not** a separate host check's indispensability.

D64 supplies those points by reconstruction, not on wire. Therefore the
future host must feed the reconstructed points into this exact verified
statement; comparing a computed point with itself would establish nothing.
That host path does not exist in this baseline, so it cannot yet be certified.

There is also an explicit redundancy: P_B=P_A makes equations seven and eight
identical, including their targets. The test asserts their equality. If only
one public handle constraint is omitted while the other correct handle and
C_t remain, the remaining handle still fixes r0; C_t still fixes T.
Consequently, the requested claim that **each** individually deleted public
handle check must permit a wrong amount is not valid. Corrupting a point while
retaining the original proof is a different experiment and cannot substitute
for it. Keep all eight equations and all three reconstructions; change the
coverage claim, not the relation, to acknowledge this redundancy.

## Host pending criterion

The test-only `withdrawal_pending` predicate compares complete account-to-
pending commitments at an isolated operation boundary, including user/system
entries and counts. Synthetic insertion in the source or a second account
is rejected. The future adapter must obtain this complete observation from
authenticated artifacts; inspecting only a proposed effects list is not enough.
No live Withdrawal installation or adapter is claimed.

## Executed evidence

The release kernel test `tests::d64_shared_witness_and_equal_handles` passed.
The existing `tests::nonidentity_handles_are_checked_before_proof_verification`
also passed. The three point corruptions reach verification error 3, not decode.
No new relation, ABI, production host code, or protocol encoding was added.

Full `cargo test --locked --offline --release --lib` passed 26/26 (2.84s).
The focused C++ accounting target passed all four tests. In an isolated copy,
removing only the pending-comparison branch made the D64 test exit 1 at its
expected-error assertion. These are not live host observations.

The changed Rust test source requires its committed file identity to be pulled
into the ABI inventory by A, who owns that inventory. No ABI call site was
added or removed. B has not edited that shared inventory or claimed it green.
