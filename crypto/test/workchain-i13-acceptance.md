# Private multi-account coverage acceptance

This unit exercises the real account dictionary/access helpers and the private
Native storage overlay. It does not enable a workchain, change a production
header, or certify the complete admitted engine/settlement/replay chain. The
new executable is separate from `test-workchain-block`.

## Inputs and independent observations

Every fixture has six distinct active Native accounts at keys beginning with
16, 32, 64, 128, 192 and 224. Two accounts normally participate. Values and
addresses are deliberately different. The test obtains three separate objects:

1. Declared read/write keys supplied to `WorkchainAccountAccess::create`.
2. Actual changes derived by `WorkchainAccountDictionary::changed_accounts`
   from the old and resulting **ShardAccounts dictionaries**.
3. Participant keys decoded from materialized **Native AccountBlocks**. The
   augmented dictionary is stripped correctly; each AccountBlock is validated
   and its account address checked against its dictionary key.

For inconsistent-input cases, the result and participant dictionaries are built
separately by successful private storage-overlay calls. The test never supplies
the same vector to both `finish` arguments. In particular, the requested update
list is only a fixture oracle for checking the independently obtained delta;
it is not used as the actual delta passed to `finish`.

All read/write ledger prerequisites deliberately succeed before the exact-set
cases call `finish`. This isolates its two equality checks. These are structural
acceptance tests, not a claim about source-aware failure classification or about
an actual engine having produced the inconsistent pair of dictionaries.

## Cases and failure identities

The executable accepts one numeric case argument, or runs all sixteen cases.
A passing case exits 0. Assertion categories are numeric: setup/private-overlay
rejection 10, delta 40, finish verdict 41, read binding 42, usage observation 43,
untouched bytes 44. Unexpected exceptions exit 2 and never count as a control's
expected behavioral result. Diagnostic strings are not used for attribution.

| Case | Property checked |
|---|---|
| 0 | Two actual changed accounts, two declared writes, two decoded participants: accept |
| 1 | Declaration includes an unchanged account; participants match declaration: reject |
| 2 | Actual result changes an undeclared account; participants match declaration: reject |
| 3 | Participants omit a changed account; actual changes match declaration: reject |
| 4 | Participants include an unchanged account; actual changes match declaration: reject |
| 5 | A declared read is never verified: reject at finish |
| 6 | Old account hash differs from declaration: reject |
| 7 | Declaration says absent but old account exists: reject |
| 8 | An undeclared key between two declared keys: reject before obtaining an expected hash |
| 9 | Real private overlay reads exactly the two participating old account bodies; four other complete ShardAccount BOCs remain byte-identical |
| 10 | Boundary example: direct dictionary replacement changes an account without loading its old body |
| 11 | Authenticated absence and a separate existing read: accept |
| 12 | Declaration says present but old account is absent: reject |
| 13 | ShardAccount metadata-only change is included in the delta |
| 14 | Deleted account is included in the delta |
| 15 | Inserted account is included in the delta |

Case 8 tests the declaration gate itself, before dictionary acquisition. It
uses an interior missing key so removing that gate does not cause an end-iterator
access or depend on a later hash mismatch. Cases 6, 7 and 12 separately test
hash/existence binding to the actual authenticated-dictionary view.

## Controls and guard attribution

The runner builds with `-j32`. Baseline and every restored run use **real
repository source and headers**. Ninja dependency records confirm the paths of
all three relevant production headers. Only the mutant build sees a temporary
copy, limited to the private test target.

Before each mutation, the runner reads the source from an explicit commit using
`git show`. It checks byte equality with the repository file and then the copied
file. Each record includes `committed_source.git_blob_oid`, the SHA256 of that
blob's contents (`blob_sha256`), `copy_before_sha256` and `mutant_sha256`.
The two SHA256 values before mutation must match; the git object ID is retained
separately because it hashes the Git object representation, not just file bytes.
Exact `from`/`to` and offsets support replay. After a compiled behavioral run,
the copy is restored byte-for-byte, its SHA256 recomputed, and the replacement
reapplied in memory to reproduce the mutant hash. The copy is then deleted,
production paths reconfigured and rebuilt, and the affected cases rerun green.

| Single mutation | Cases | Required mutant exit and attribution |
|---|---|---|
| Route overlay dictionary writes to the last existing participant key | 0 | 10: the private overlay refuses to return a result, before the outer delta oracle could exit 40 |
| Remove actual-change equality | 1, 2 | 41: participant equality and all ledger prerequisites remain satisfied |
| Remove participant equality | 3, 4 | 41: actual-change equality and all ledger prerequisites remain satisfied |
| Remove unused-read check | 5 | 42: empty writes and both empty finish lists satisfy the other finish checks |
| Remove old hash/absence comparison | 6, 7, 12 | 42: declared keys exist in the ledger; the actual dictionary observation is the differing value |
| Admit an undeclared interior read | 8 | 42: no later hash comparison is invoked |
| Remove difference-key collection | 13, 14, 15 | 40: direct dictionary cases do not run overlay/ledger checks that could hide this failure |
| Remove usage observation | 9 | 43: required positive reads disappear, proving the observation is not empty by construction |
| Load an unparticipating old body | 9 | 43: returned state remains valid and unchanged; only the read footprint differs |
| Alter an unparticipating result account | 9 | 44: old-body usage still passes; the later BOC comparison detects the alteration |

The overlay-routing control retains sorted declarations and physical records,
valid account bodies, valid timing and successful writes to an existing key.
The first participant's value is temporarily written under the second key and
then overwritten by the second participant's valid value. The final dictionary
is structurally valid but changes only the second account. `record_write` still
sees both correct declared keys; physical participants still contain both keys.
Only actual-change coverage rejects this constructed final state. Thus this
control exercises the overlay's own result-dictionary check, not just the
outer test's independent recomputation. Exit 40 would indicate that the overlay
returned the inconsistent state and is not the accepted result for this control.
The condition relies on this specific two-existing-account fixture; it is not a
general error-code classification of all possible overlay failures.

## What the usage evidence establishes

Case 9 installs `CellUsageTree::ScopedReadObserver` on a tracked old dictionary
root for the actual private overlay call. It classifies loads by the six unique
old account-body hashes. The two participating bodies must be observed; none
of the other four may be observed. Dictionary spines and augmentation cells may
be read and are not mislabeled as loading an account body. The observer covers
repeated attempted loads, not just a first-load callback.

After the observer is removed, the small fixture's four untouched entries are
serialized, including their full account closures and ShardAccount metadata,
and compared byte-for-byte. This fixture oracle is not a proposal to traverse
and compare every account in a production shard. Production delta extraction
uses the existing `scan_diff` subtree hash skipping, with its documented old-root
validation and input-budget preconditions.

**Unread does not unconditionally imply unchanged.** Case 10 constructs a
replacement account and substitutes its reference in the persistent dictionary
without loading the old body. The usage observation remains empty for that body
while the independently computed delta contains its key. This is a limit of
usage tracking, not evidence that the restricted storage overlay performs such
an undeclared write. The I13d evidence is therefore a combination of restricted
host construction, independent delta/participant coverage, observed absence of
unparticipating body loads, and a bounded byte oracle. Usage silence alone is
not used as an immutability proof.

## Remaining scope

This unit does not establish the entire M1 invariant chain: complete admitted
engine integration, allocation/payout-specific overlays, validator replay,
publication/commit atomicity and large-shard cost bounds are outside these
cases. Physical AccountBlock validation here does not replace full transaction
relation/binding replay. The usage test has a concrete six-account scope; it is
not a universal proof about every unvisited branch or every future host API.
No claim of milestone acceptance follows from the harness passing.

The archived measurement is `doc/measurements/uno-m1-i13-acceptance.json` with
full stdout/stderr artifacts (including empty files). Early development runs
and the initial copy-based baseline are not delivery evidence. The accepted
measurement must match the committed-source and production-baseline conditions
above. Coordinator review is pending.

## Reproduce

Use fresh work/output paths; an existing build directory can be reused. The
runner sets up the private target through `CMAKE_PROJECT_TOS_INCLUDE` and never
modifies the root CMake file or the shared test source.

```sh
python3 crypto/test/workchain-i13-acceptance.py \
  --build /tmp/i13-build --work /tmp/i13-control-copies --output /tmp/i13-evidence
```
