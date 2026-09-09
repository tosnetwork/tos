# Primitive patch differential

This is a shared-base comparison of local patch semantics. It is not independent
implementation verification. It provides no external oracle for SEND/COLLECT;
the relation-level limitation recorded by D34 remains. This first unit covers
proof byte preservation by the four constant-time inner-product MSM changes.
It does not close the independent-residual or RNG acceptance items.

Run from the repository with an acquired bare repository containing the pinned
upstream commit and original annotated tag object:

```sh
python3 uno/crypto/tests/patch-differential.py \
  --upstream-git /path/to/bulletproofs.git \
  --work-dir /tmp/unique-differential-work \
  --output /tmp/unique-differential-evidence
```

Both destination directories must be new. Missing tools, sources, dependency
archives, build failures, producer failures and incomplete corpora fail the run.
Dependency preparation can access the network; builds are locked, offline and
use `-j32`. The runner does not alter the node manifests or dependency checkouts.

The upstream tree comes from `git archive` of the pinned commit, with every
vendored upstream blob checked against the source manifest. Its Cargo manifest
and Rust sources remain unchanged. Harness-level Cargo patches route both
source URLs to clean dalek/Merlin checkouts at the authenticated revisions.
The harness lockfiles must describe identical packages. Both harnesses enable
`std`; this graph is solely for differential testing, not the minimal verifier
feature audit. The local side is an isolated copy of the authenticated vendor.

The corpus contains 18 inner-product proofs (lengths 1, 2, 4, 8, 64, 256) and
72 aggregated range proofs (8, 16, 32, 64 bits; 1, 2, 4, 8, 16, 32 values),
using three reproducible test seeds. Range inputs include zero, maximum values,
one, random in-range values and identity commitments. Each record compares the
complete proof, commitment bytes, post-proving transcript challenge and subsequent
RNG output. The first differing field has a structured guard identity. The
generator deliberately does not run proof verification: a bad proof must reach
the byte-comparison guard without an overlapping verifier assertion catching it.

Four isolated controls add one incorrect Q contribution to one L/R MSM at a time.
Each producer must compile and exit successfully before `proof-bytes` fails.
The original file is restored byte-for-byte after each control; the report gives
the offset, exact from/to bytes, original/mutant/restored hashes and a restore
audit that reapplies the replacement to the restored source. A final rebuilt
baseline must again match all 90 records. Reverting CT to variable-time MSM is
expected to preserve these bytes and is therefore not a negative semantic
control; the separate provenance gate protects retention of the CT implementation.

Evidence contains full build diagnostics, exit statuses, binary/corpus hashes,
the resolved lockfile hash and compiler identity. TSV files retain complete
corpora without log truncation. Finite inputs are empirical regression evidence,
not a proof that all possible witnesses or platforms behave identically.
