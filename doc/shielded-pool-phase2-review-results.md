# Phase-2 conformance review and rehearsal — 2026-09-22

> ## Disposition, added 2026-09-22 after the review landed
>
> The review is kept as written, including its paths. Those beginning
> `artifacts/phase2/` refer to the **first** ceremony, which was withdrawn and
> whose directory was removed; its files remain in history at `7ec052e00` and
> `7ed85e8dc`. `artifacts/phase2/` now holds the replacement ceremony.
>
> What was done about the review:
>
> | finding | status |
> |---|---|
> | **R1** summary transcript outside the final audit | **fixed** — `phase2-verify` now compares the computed ending against `record.transcript` |
> | **R2** provenance and dimensions printed as facts | **fixed** — the ceremony name and both dimensions are compared against reconstructed values before anything is printed |
> | **R3** malformed digests panic | **fixed** — every digest in a record is validated as 64 hex characters before anything indexes it |
> | `pok-challenge-points` survivor | **closed by the review's own test.** It found the concrete counterexample I could not build: publicly rescaling `s` and `s_delta` by 2 leaves the proof equation intact if the challenge omits them. The mutation is now killed by name and **no recorded survivor remains** |
> | stale `crosscheck.rs` comment about shared weights | **fixed** — each side draws its own, which the comment now says |
> | wipes bypassed by early `?` returns | **fixed** — `secret.rs` and `entropy.rs` use `Zeroizing`, so the buffers are wiped on every exit rather than only the successful one |
> | beacon is an already-mined block | **not a defect; a recorded choice.** `artifacts/phase2/ANNOUNCEMENT.md` states what it gives up and that a redo should use a future height |
> | announcement-before-contribution not provable from the checkout | **correct, and unfixable here.** Only external publication can evidence it |
> | contribution 1 unsigned and operator-controlled | **as stated in its own attestation.** The ceremony rests on nobody until contribution 2 |
>
> `test/shielded-pool/review-phase2-cli.py` was a reproducer asserting the
> defects were present. It now asserts the refusal **and names the reason**,
> so a refusal for some other cause cannot keep it green.
>
> The review's own caveat is worth repeating: it did not run the
> secret-formatting mutation, correctly, because doing so would have violated
> the handling rules. That case is still covered when the battery is run by
> someone who accepts that one mutation prints a scalar to a local terminal.


Reviewed revision: `16f8d9aef6dc53a116d249dd244c076c08350f3c`, branch
`feat/shielded-pool`, in a fresh clone at
`<review-checkout>`.

Updated on the user's request to
`7ed85e8dc07ae5d57c62b56168df331b96c922a2`. The three intervening commits
change documentation and add the published ceremony artifacts; they do not
change tools, scripts, tests or the phase-1 slice. The baseline mathematical
tests therefore cover the same implementation. The newly published phase-2
directory was separately read and verified without modifying it.

This report follows `doc/shielded-pool-phase2-review.md`. All ceremony runs
are rehearsals. No signing key is generated and no ceremony directory is
retained or published. Production source changes are outside this review.

## Status

The implementation's central arithmetic and the rehearsal pass. Three
record-validation defects are reproduced below. This is not production
acceptance: the published ceremony is unfinished, has one unsigned contribution
under the operator's control, and deliberately uses an already-known beacon.

## Published directory at the updated revision

Read `artifacts/phase2/{README.md,ANNOUNCEMENT.md,attestation-1.txt}` and the
JSON record, then ran `phase2-verify artifacts/phase2/ceremony` without a
VK output path. It exited successfully, rebuilt the expected starting key,
audited one contribution, and explicitly reported **NOT FINISHED**.

- `key.bin`: 5,949,456 bytes; its SHA-256 agrees with the record.
- `contributions.bin`: 672 bytes; its SHA-256 agrees with entry 1.
- `beacon.bin`: 64 ASCII bytes; its SHA-256 agrees with the announcement.
- The summary transcript agrees with the entry's transcript in this directory.
- Both [Blockstream](https://blockstream.info/api/block-height/968100) and
  [mempool.space](https://mempool.space/api/block-height/968100), queried in this
  review, returned the announced block hash.

The announcement explicitly chooses an already-mined block. Pinning a known
value prevents changing that value at close, but does not meet the future
unpredictability assumption in the construction's beacon argument. The
mathematical audit cannot certify that procedural property. A conformance
claim to the random-beacon model would require a future round and a contribution
cutoff before its output is available, or a separately justified security
argument for omitting that property.

The announcement and revised contribution first appear together in the latest
Git commit; the previous commit already contained a different contribution.
This checkout does not independently prove the assertion that the revised
announcement was publicly available before the revised contribution. External
publication evidence is needed; this is not an assertion that no such
publication occurred. The unsigned statement likewise cannot prove erasure
or an independent participant's involvement.

## Claims and construction

1. **Deterministic starting key:** the map in `phase2.rs` uses the supplied
   phase-1 group elements and the circuit matrices, with gamma and delta one.
   It introduces no new phase-2 secret; the phase-1 secrecy assumptions still
   apply. The small-circuit equality and determinism tests pass. The separately
   ignored full-circuit comparison also passes element for element against
   the pinned arkworks generator.
2. **Contribution arithmetic:** `apply` multiplies both delta points and
   divides L and H by the same scalar. The verifier compares all other key
   sections and batches the two query relations. The focused tests pass.
3. **Knowledge-proof construction:** the code hashes the transcript, `s`, and
   `s_delta` into G2 with a dedicated domain, then publishes its scalar
   multiple. Pairing checks bind both the proof and the delta transition.
   This matches the construction used in the reference implementation. It
   is not a new proof of knowledge soundness for this implementation.
4. **Audit without intermediate keys:** each contribution is 672 bytes; the
   audit starts from a rebuilt key, advances the public transcript and delta,
   and compares the final L/H queries against the initial ones. The chain
   tests exercise this without supplying intermediate keys.
5. **Beacon:** the corrected no-secrecy/no-full-collusion-rescue statement is
   correct. The public beacon multiplier cannot hide a product already
   known by a coalition. Exact beacon recomputation is present and tested.
   A future, independently unpredictable output and a predetermined schedule
   remain procedural assumptions, not consequences of a 32-byte length check.
6. **Gamma one:** supported by BGM17 section 6, which removes the gamma
   terms using the extended CRS, and by the reference implementation setting
   `gamma_g2` to the generator. This is a statement about this construction,
   not a claim that any arbitrary Groth16 setup may expose its trapdoors.
7. **QAP domain:** `constraints + instance_variables`, rounded up to the
   supported evaluation domain. The explicit input-consistency rows in
   `phase2::initial` and the degree tests agree. The current circuit fits
   the committed degree-32768 slice.

Primary references checked:

- [BGM17, sections 3.7 and 6](https://eprint.iacr.org/2017/1050).
- [Reference phase-2 implementation](https://github.com/ebfull/phase2/blob/master/src/lib.rs).

## Known soft spots

- `pok-challenge-points`: reproduced as a survivor of the original suite,
  then killed by a new public-rerandomization regression. Given a published
  contribution, replace `s` with `2s` and `s_delta` with `2s_delta`, leaving
  `r_delta`, delta and the key unchanged. If the challenge omits the two
  points, bilinearity preserves the proof equation, and both the knowledge
  proof and chain checks accept the changed bytes. With the real challenge,
  the proof-of-knowledge check refuses. The transformation never accesses
  the contribution scalar. This is a concrete binding/malleability counterexample
  for the weakened verifier, **not** recovery of toxic waste or a forged
  pool transaction; it does not establish a general knowledge-soundness break
  for arbitrary fresh transcripts. The new test first accepts the original
  chain, then requires the correct refusal from both step and chain verification.
  An independent temporary source/build tree with only this hash mutation
  turned the test red for the expected acceptance. The mutation harness now
  names the new test. BGM17 and the reference implementation support retaining
  the point binding; the new test is additional executable evidence.
- The blst checker independently exercises pairing/group arithmetic, but
  shares challenge construction, encoding and protocol meaning. The agreement
  tests pass; they do not provide an independent protocol proof. Its comments
  about sharing weights are stale: `crosscheck_agrees.rs:103-114` actually
  draws separate weights for the two verifiers.
- The compensating-pair test checks that unweighted sums cancel before asking
  the two verifiers to reject. This is relevant evidence for random weighting,
  rather than a malformed-point rejection disguised as a batching test.
- `Secret` keeps redacted Debug and has no Display/Serialize/Clone/Copy.
  Its Drop wipes its field. Wiping remains best effort: the early error at
  `secret.rs:71` bypasses the explicit wipe of `wide`; similarly,
  `entropy.rs:145-148` bypasses the final wipe of `fresh`, and `stirred` is
  not explicitly wiped. No secret-memory inspection was performed. These
  observations do not demonstrate remote extraction or a public-artifact leak.

## Review-script safety conflict

`mutations-ceremony.py` includes `secret-printed`, which replaces redacted
Debug with scalar formatting. Executing it would directly violate review
rule 0.1. It was excluded; the remaining mutations preserve redaction.
The ordinary redaction test was run. The mutation results must not be
described as a complete 45-case run.

## Reproduced findings

### R1 — The summary transcript is outside the final audit (medium)

**Where:** `tools/shielded-pool-ceremony/src/bin/phase2-verify.rs:170-183`.

**Claim versus code:** the record declares `transcript` to be the current
transcript. The final verifier checks each entry's `transcript_after` but
never compares the computed ending against `record.transcript`. In contrast,
both contribution and finalisation commands require that comparison.

**Reproduction:** the `false-transcript` case in the added CLI reproducer
changes only the top-level field to 64 zeroes. The verifier exited zero and
still called the ceremony finished.

**Impact:** an artifact supplier can obtain a successful final audit of an
internally inconsistent record. This can mislead software or people relying
on the published summary digest. It does not let that supplier change the
verified contribution chain, the actual key, or a correctly checked signed
per-entry attestation. No proof forgery is demonstrated. Compare the final
computed transcript with the summary before exporting a VK.

### R2 — Unchecked provenance and dimensions are printed as facts (medium)

**Where:** `tools/shielded-pool-ceremony/src/bin/phase2-verify.rs:100-125`.

**Claim versus code:** the verifier prints `record.phase1_transcript` and
`record.constraints`. It compares the slice digest and starting-key digest,
but never checks the ceremony name, constraint count or instance-variable
count against its reconstructed values.

**Reproduction:** `false-provenance` sets the name to
`review-false-provenance` and both dimensions to one without changing any
cryptographic artifact. The final audit succeeded while reporting the false
name and constraint count.

**Impact:** an artifact supplier can falsify human-facing provenance and
dimensions in an accepted record. The digest checks still bind the real
slice and circuit, so this is a custody/reporting-integrity defect, not an
ability to substitute a different cryptographic circuit. Display reconstructed
values and require the corresponding record fields to agree.

### R3 — Malformed digest strings panic before a reasoned refusal (low)

**Where:** `tools/shielded-pool-ceremony/src/bin/phase2-verify.rs:101`, also
the error paths at lines 115 and 123; `record.rs:196-203` accepts strings
without digest-format validation.

**Reproduction:** `short-digest` sets `phase1_slice_sha256` to `x`.
The reproducer confirmed a panic from the unchecked `[..16]` access. A multibyte string can also
make a byte-indexed slice land inside a UTF-8 code point.

**Impact:** a supplied malformed directory can crash the local audit process
instead of returning `REFUSED` with the intended reason. It does not produce
a successful audit or demonstrate fund loss. Parse digests as fixed-size
bytes, and validate their hexadecimal syntax before display or comparison.

## Validation record

- Release binaries built successfully after downloading missing dependencies.
- Default release tests: **121 passed, 0 failed, 2 ignored**. The ignored
  cases are the full-circuit initial-key comparison and contribution test.
- Full-circuit initial-key comparison: **1 passed**, 197.00 seconds. This
  ran the original release test executable built by the baseline test run;
  it was not recompiled from a temporarily mutated source file.
- Full-circuit contribution and proof verification: **1 passed**, 124.77
  seconds; 18,107 constraints, L=18,215, H=32,767. The test measured 7.3
  seconds contributing and 0.3 seconds auditing inside this run.
- Safe mutation subset, before the review's new test: **44 mutations, 43
  killed by their named tests, 1 recorded survivor**, and the restored suite
  passed. The harness used release mode; no secret-formatting mutation ran.
- Isolated CLI rehearsal: begin, two contributions (including stirred-in
  entropy), finalise and verify passed; 1,248-byte VK, 2,016-byte contribution
  file. All ten existing refusal invocations failed for the expected reasons.
- Three additional malformed-record cases reproduced R1–R3.
- New proof-binding regression: passed on original code; failed by name
  when the two challenge inputs were removed in an independent temporary
  build. No other production check was weakened and no scalar was displayed.
  The updated original mutation harness was also run for this case alone:
  baseline green, named test killed the mutation, restored suite green.
- Final focused regression suites: **44 passed**, one default-ignored full
  circuit test (already run explicitly above). Python syntax and whitespace
  checks passed. All production source and upstream ceremony files match HEAD.
- All rehearsal directories were deleted, including the discarded run.
  No signing key was generated. The upstream published directory was left
  untouched; it is not a rehearsal created by this review.
- No contract deployment or production ceremony contribution/finalisation
  was performed. The separate on-chain acceptance gate and
  phase-1 transcript custody history are outside this review's validation.

Compact execution output is retained in
[`shielded-pool-phase2-review-evidence.txt`](shielded-pool-phase2-review-evidence.txt).

An initial overlapping rehearsal was discarded: the mutation harness also
rebuilds CLI binaries, so a simultaneously running rehearsal can pick up a
mutated executable. Its failure is not counted as a defect in the reviewed
revision. The temporary directory was removed. Final rehearsal results must
come from an unmodified build after mutation restoration.

## Reproduction

From the repository root, after the mutation harness has finished and restored
all source files:

```sh
cargo build --release --bins --manifest-path tools/shielded-pool-ceremony/Cargo.toml
python3 test/shielded-pool/review-phase2-cli.py
```

The added reproducer wraps the existing CLI suite in `TemporaryDirectory`, so
cleanup also occurs on ordinary exceptions. It checks additional edits to
the summary transcript, descriptive provenance/dimensions, and digest length.
It is a reproducer of the reviewed revision's behavior, not a production
acceptance gate; a reproduced erroneous acceptance is still a finding.
