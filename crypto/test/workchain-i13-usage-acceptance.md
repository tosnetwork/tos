# Partial-old-state coverage acceptance

This supplements the multi-account coverage unit with three private
storage-overlay executions whose old-state proofs cannot supply any of the four
unparticipating account bodies. The participating pairs are `(16,128)`,
`(32,192)` and `(64,224)` in the same six-account fixture, so every account is
both participating and unparticipating across the cases.

**The pruning is deliberately constructed by the test to check non-dependence.
It establishes no production `VmVirtError` classification.** Forbidden pruned
structure supplied by a candidate must be rejected as `CandidateInvalid`;
missing authenticated local state belongs to `LocalUnavailable`. Seeing that
exception alone does not identify its source. These tests exercise a known
fixture source, not a candidate/local-state classification boundary.

## What is physically unavailable

The full-state private overlay runs through `MerkleProofBuilder` first. For
fixture preparation only, the test then exposes the six dictionary entries
without loading unused account bodies. This makes each dictionary path available
in the extracted proof and isolates missing **bodies**, rather than accidentally
failing earlier while looking up an unavailable dictionary path. This six-entry
proof-shaping step is not a proposed full-shard traversal in production.

The proof is extracted and virtualized, and its old-root hash must equal the
original root hash. For every account, the test successfully decodes its
ShardAccount entry and checks the referenced account hash. Only then does it
try loading that account body. Both participating bodies must load. Each of the
four other bodies must throw the exact native identity:

* exception type `vm::VmVirtError`;
* `get_errno() == vm::Excno::virt_err` (14);
* `virtualization == 1`.

A different native exception does not satisfy this condition. A mismatching
virtualization identity fails separately with test exit 57. The test requires
four unavailable bodies explicitly; completion of the overlay alone cannot
make this check pass. This establishes unavailability in the proof supplied to
the tested call, not the absence of full fixture data elsewhere in test memory.

## The tested private execution

The same overlay is called with a usage-tracked wrapper around the partial old
root. It receives participating keys, their expected old hashes and new payloads;
it receives no unparticipating account-body reference. An observer attached to
this exact partial-root usage tree must see precisely the two participating old
bodies. The execution scope maps only the exact pruned-body exception above to
test exit 52. Other assertion/exception outcomes remain distinct.

After execution, the test independently derives changes from the partial old
and returned account dictionaries, decodes the returned Native participant
records, and requires both sets to equal the selected pair. Both returned root
hashes must match the full-state reference execution. Native AccountBlocks are
also compared byte-for-byte as BOCs. For all four unparticipating entries, the
returned account hash remains bound to the original hash and body loading still
raises the exact pruned-body exception. Returned unread content is not silently
rehydrated from the full-state oracle.

Full untouched-account byte comparisons remain in case 9 of the preceding unit;
this unit cannot serialize unavailable body contents and does not pretend to do
so. Its root/reference comparisons rely on the existing content-hash model.
Together the observations cover the private fixture paths. They do not prove a
universal property of every future input or production engine/replay path.

## Compiled controls

The helper fixture is reused by including its unchanged source with its `main`
identifier renamed locally. This avoids editing the previously measured file.
Its source hash, the new source hash, the three production headers and native
exception definition are all checked against explicit committed blobs before
measurement. Baselines and restored builds use real repository files. Mutants
use one temporary test-source copy; all production headers remain real repository
headers throughout. Ninja dependency captures check those exact paths and reject
a copied source leaking into a restored build.

Every control runs all three cases. The numeric identities distinguish each
observation stage; error text is never the discriminator.

| One source replacement | Required exit | Isolated observation |
|---|---:|---|
| Use the full old root instead of the extracted proof | 51 | The four required unavailable bodies are actually available; pruning check fails before execution |
| Explicitly load one known unavailable body inside the execution scope | 52 | Exact native errno 14 / virtualization 1 is caught; this is not generic failure |
| Execute against the full old root instead of the tracked partial root | 53 | Earlier pruning checks pass, but the required reads through the partial input disappear |
| Remove the observer's recorded reads | 53 | The required positive reads disappear, proving the instrument must speak |
| Replace the full-state account-root oracle | 55 | Delta and participant checks pass; account-root equality fails |
| Replace only the full-state AccountBlocks-root oracle | 58 | Account-root equality passes; the distinct block-root comparison fails |
| Serialize a different block oracle after both hash checks | 59 | Both root-hash checks pass; byte comparison alone fails |
| Replace the returned partial account root with the equal-hash full root after comparisons | 56 | Prior checks pass, but the returned unparticipating bodies are now loadable |

The two controls returning 53 intentionally exercise **one guard**:
`observed == std::set<unsigned>(selected.begin(), selected.end())`. Bypassing the
partial input removes reads from the tracked tree; removing observation prevents
those reads from being recorded. Both violate the same required-observation
predicate from different directions. They are not two independent defenses, and
53 identifies that predicate rather than diagnosing the underlying cause.

The control record contains the committed blob ID and content SHA256, copy
before/after SHA256, exact single `from`/`to` occurrence and offset, compilation
result, numeric case outcomes and restored SHA256. The restored bytes reproduce
the archived mutant hash when the replacement is reapplied. Each copy is then
deleted and all three cases rebuilt/rerun against the original repository source.
No build failure or unexpected native exception counts as behavioral evidence.

## Evidence and remaining scope

`doc/measurements/uno-m1-i13-usage-acceptance.json` and its adjacent directory
retain the per-case baseline, mutant and restored results, exact native exception
identity on deliberate missing-body loads, dependency captures and full logs.
Captured empty stdout/stderr files are retained. Coordinator review is pending.

The result demonstrates that these three private storage-overlay runs and their
independent delta checks complete when unparticipating old bodies cannot be
loaded. It does not establish production error classification, full admitted
engine/settlement/replay coverage, publication atomicity, universal absence of
hidden dependencies or asymptotic full-shard cost. The first unit's counterexample
still applies: arbitrary reference replacement can change an unread body, so
usage silence alone is not an immutability proof. Workchain activation remains
closed, and no production header was changed.

Reproduce with fresh work/output paths:

```sh
python3 crypto/test/workchain-i13-usage-acceptance.py \
  --build /tmp/i13-usage-build --work /tmp/i13-usage-copies --output /tmp/i13-usage-evidence
```
