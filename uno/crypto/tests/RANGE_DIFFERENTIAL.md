# Range patch acceptance and residual comparison

This unit follows the nonzero outer-factor baseline approved in D41
(decision record memo@91ef26f9). The zero outer-factor case remains a separate
exception: it removes the entire check, whereas a c-collision cancels nonzero
residuals. Under honest sampling, `Scalar::random` returns zero with probability
approximately 2^-252. The chosen-output probe is **not a claim of a practical
attack**. The independent verifier has no outer factor to undergo this
degeneration. No execution permission or milestone acceptance is changed here.

Run after the CT unit has completed and restored its work directory:

```sh
python3 uno/crypto/tests/range-differential.py \
  --ct-work /tmp/restored-ct-work \
  --upstream-git /path/to/bulletproofs.git \
  --work-dir /tmp/new-range-work \
  --output /tmp/new-range-evidence
```

The runner reauthenticates the original annotated tag and peeled commit, the
complete upstream file inventory and every blob against the Git tree, the
vendored subset against its source manifest, and the clean dalek/Merlin
checkouts against their pinned commits. The upstream Rust and Cargo sources
are unchanged in the baseline. Both harness lockfiles are retained and must
match. Builds are locked, offline, and use `-j32`; missing inputs/tools fail.
The 72 valid range proofs come from the archived upstream CT corpus, not a
local generator run inside the acceptance test.

## Black-box acceptance and feature behavior

The corpus has 357 cases: 72 valid proofs across all supported bit sizes and
aggregation sizes through 32, a canonical altered e-blinding response for
each, wrong domains, and a field/commitment/codec/parameter matrix at two
selected shapes. That matrix includes identity and invalid points, canonical
and invalid scalar slots, truncation, trailing bytes, wrong bits, insufficient
generators/parties, empty commitments and non-power-of-two commitment counts.

The upstream randomized API is given chosen **nonzero** outer factors 1, 2,
and 255; all three runs must agree, including final transcript state. This is
test instrumentation for an upstream API, not fixed-seed randomness added to
the authoritative verifier. The local original API must match upstream in all
357 acceptance results and transcript tails. The local independent API must
match acceptance and tails for accepted proofs. Rejected-input tail equality
is not required across the split because its preflight checks can reject
earlier; all tails are nevertheless archived.

The independent result is also compared byte-for-byte with Bulletproofs `std`
disabled and with `kernel-test` enabled. This exercises the allocation/feature
boundary and test-only export patches without conflating these test harnesses
with the separate minimal node-verifier graph. Dependency selection, the
original API, and these feature configurations provide finite behavioral
coverage of the remaining three metadata/module/export patches. Disabled R1CS
and benchmark targets are not claimed as part of this verifier corpus.

## Residual observations and c-collision boundary

After the untouched baseline, one temporary source at a time receives a
read-only observation statement. Upstream records the actual point immediately
before `BatchCollector::verify` tests identity. The local observer records the
actual IP residual, polynomial residual, c, and `ip + c*poly`, immediately before
the independent predicate. Factor 1 removes outer scaling from the comparison.
Both observers must preserve the complete baseline stdout, including rejected
results and transcript tails; all observer edits and restoration hashes are
recorded separately from semantic mutations.

There are 258 inputs that reach both residual observation sites. The upstream
point must equal the reconstructed local point for every one. In 72 altered
e-blinding cases, the observed polynomial residual must be zero and IP residual
nonzero. This provides an input on which omitting only the IP guard changes
acceptance and the polynomial guard cannot accidentally catch the defect.

The residual-boundary corpus exercises the actual exported independent
predicate on `(0,0)`, `(G,0)`, `(0,G)` and 16 pairs `ip = -c*poly` with nonzero
c and nonzero poly. The combined expression is identity and the actual split
predicate rejects. These are **synthetic residual-boundary inputs**, not full
Fiat-Shamir proof forgeries. The connection to the original upstream equation
is the preceding observed residual comparison plus the existing algebraic
review. Finite samples cannot prove there are no other divergences on all
possible inputs, and no claim of such a universal empirical proof is made.

Collision rows have four columns: case ID, `ip + c*poly` is identity, actual
predicate acceptance, and c bytes. In `merge-residuals.tsv`, the second column
is 1 for all 16 rows, while the third column is 1 only for case 0 (c=1).
The unweighted merge mutation accepts one of these 16 inputs, not all 16.

## Attributed controls

Every semantic control compiles, runs to completion, and fails a specific
structured criterion; error strings are not used for attribution:

| Single change | Consulted guard | Distinguishing input |
|---|---|---|
| Flip polynomial blinding sign | `acceptance` | Valid proof rejects after one coefficient changes in committed source |
| Omit IP check | `acceptance` | Altered e-blinding with observed zero polynomial residual |
| Omit polynomial check | `residual-poly` | `(0,G)` accepted only by the missing polynomial guard |
| Merge residuals with coefficient one | `collision` | Nonzero `(−G,G)`; both one-residual cases still reject |
| Omit c transcript event | `transcript-tail` | Valid proof still accepts, but post-verification challenge changes |

The sign control starts directly from the committed source with no observation
adapter. `--only-polynomial-sign` reruns this control and its baseline/restored
checks without repeating the other controls. The rerun supersedes the initial
sign-control record whose baseline included the read-only observer. The rerun
measures the acceptance guard; it must not be cited as a mutation control of the
observed-residual comparator. Each record includes exact from/to bytes and
original, mutant, restored and replay hashes. A final rebuilt baseline must
match, and both source trees are reauthenticated after all observations and
mutations.

This remains shared-base patch regression evidence. It is not independent
implementation verification and does not provide an external SEND/COLLECT
relation oracle. The D34 limitation remains unchanged.
