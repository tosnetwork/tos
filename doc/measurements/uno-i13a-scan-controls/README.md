# I13a mechanism and private acceptance evidence

Final measured result: 27/27 runtime mutation controls restored and reproduced;
required-source compile controls passed. Complete default build passed. Ordinary
JUnit records 130 actual cases: 121 passed, 9 owner-deferred, 0 unresolved, 0
skipped (raw CTest exit 8, not an all-green CTest claim). The private scan passed
separately; five private checks are statically registered, not all run here.
Fixture cleanup was 9 -> 0 with 194 diagnostic files archived before deletion.

This unit builds the bounded host scan mechanism, not live I13a enforcement.
No collator/validator implementation, root CMake, activation gate or deployment
configuration changes. Live account_blocks_dict_ integration remains open.
The current source retains one collator refusal and three validator refusals
with `multi-account admission and replay are not connected`; the separately
identified registry required-workchain refusal also remains. Counting these
strings alone does not establish runtime connectivity.

## Reproduction and scope

`spec.json` lists 27 single-site runtime mutations. Each completed directory
contains original/mutant/restored build and CTest commands, raw JUnit, and an
audit binding exact header/test/driver/module source bytes. Mutant binaries differ
for C++ source changes; restored binaries equal originals. Driver-only mutations
need not change a C++ binary. `reproduce.py [commit]` independently reconstructs
each mutation and checks source, binary and JUnit identities. It does not replace
execution of the archived commands. Only a compiled mutant with CTest Failed at
the required assertion counts; missing dependencies and compilation failures do
not count as runtime evidence.

Every restoration explicitly rebuilds `test-workchain-batch-scan`. The complete
execution chain is CTest -> Python driver -> that binary; Ninja runs only for
source-selection observations. No hidden Counter tools or nested harness builds
are used. The driver itself is not a whole-dependency freshness attestation.

`final/source-required.json` separately records compile-time interface controls:
explicit provenance compiles, omission fails, adding a default makes the test's
`source.must_be_explicit` assertion fail, and exact restoration compiles again.
These are compile-time evidence, not additional runtime guard failures.

## Isolated obligations

- `count`: one actual identity, claim two; no uniqueness/bound violation.
- `unique`: two identities, truthful claim two, account bound three.
- `later-account`: a second identity in another account, running the isolated
  `--later-only` mode so omission fails `scan.second_account_observed` itself.
  The ordinary private test also contains these assertions; the override selects
  this mutation's first failure, not an otherwise unregistered acceptance case.
- `positive`, `identity-readback`: valid three-account/one-identity acceptance,
  count one and both returned identity hashes, not an always-rejecting scanner.
- `candidate-provenance`, `local-provenance`: the same actual pruned cell under
  two explicit representation sources gives opposite typed classifications.
- `entry-level`: an ordinary entry root with a pruned descendant has level > 0;
  removing its level check fails the representation-reason assertion, not a
  generic local error. Readable mismatched commitments are separately rejected
  by `entry-binding` as CandidateInvalid/EntryCommitment.
- `entry-input-load`, `entry-effects-load`: level-zero available special roots
  isolate the load checks from the independent level check. The old pruned-leaf
  omission mutations would now be masked by that second guard and are replaced,
  not presented as final-source evidence.
- `partial-count`: incomplete traversal after one observed record cannot compare
  that partial count with the claim. Its mutation specifically targets an
  acquisition failure after a record; this excludes the earlier level fixture.
- Separate mutations cover authenticated bounds, pre-allocation ordering,
  allocation versus candidate failure, missing/exotic classification, completed
  versus partial reporting, record/entry multiplicity, participant position,
  AccountBlock/Transaction addresses, LT binding, mounted driver failure and
  explicit completion output. See spec.json for every identity and exact edit.

## Review and invariant disposition

The source-provenance re-review found no blockers. It independently checked the
two real validator paths, exception coverage, producer accessor and wire framing.
The scanner uses get_hash(), matching the unchanged producer. With a level-zero
guard, changing only that accessor to get_hash(0) is black-box unobservable; no
independent behavioral control is claimed for that spelling. Removing the level
guard is observable, and removing it together with changing the accessor can
wrongly accept a pruned-descendant representation. This dependency is disclosed
in the mechanism document, not misrepresented as a redundant level guard.

Exact ordinary-root and closure guarantees, plus raw AccountBlocks versus
virtualized collated-data provenance, are documented in
`crypto/test/workchain-batch-scan.md`. Ordinary local root construction is not
an ordinary full-closure guarantee. For the current raw-block validator path,
its earlier root-level check is already protective; this private scanner does
not claim a newly reachable live guard there. Embedded Merkle objects can mask
descendant levels; this scan is not full closure validation.

The redundant `label.l_bits > remaining` check was removed because successful
LabelParser parsing already guarantees it, so no independent triggering input
exists. Validity is checked before inspecting l_bits, which may be uninitialized
after failed parsing. Draft review's singleton-tag/profile conflation was not
adopted: singleton wire v2 is a different family, not this admission version.
Its suggestion that claimed-count checking cannot affect acceptance was also
not adopted: the isolated one-identity/claim-two mutation demonstrates otherwise.

Earlier draft checkpoints are outside this final archive. A fixture compile
error and a compiler-diagnostic wording mismatch are not runtime controls. One
partial-count mutation first failed at the newly added level test; it was
restored, excluded and narrowed before recording the intended assertion.

## Regression boundary

The manual-only workflow now registers five private checks. This unit executes
the scan separately and statically verifies all five registrations; it does not
run the original expensive three harnesses or claim them in ordinary regression.
The workflow observation self-test retains all five names while forcing one
real CTest failure, and rejects the result under normal Python and Python -O.

Full default build, ordinary JUnit totals, fresh fixture cleanup counts and
per-case dispositions are in final/. The nine adjudicated cases await genesis
installation and corresponding identity/fixture migration. Genesis installation
is legal under the 2026-09-09 owner revision (memo f07a7ff4); the withdrawn
zero-state prohibition is not used as a reason. Raw outputs are preserved and
each cause is rechecked, not accepted merely because the number is nine.
The independent retired-domain scan has known B-owned generated-tag comment
findings; no all-CI-gates-green claim is made and no exception is broadened here.
