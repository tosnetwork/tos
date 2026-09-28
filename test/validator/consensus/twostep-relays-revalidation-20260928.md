# Revised two-step relay tests: local revalidation

## Revisions and result

- Independent review revision: `7c2c154bdfc4095cf8a716910e733875a4e3ea77`.
- Clean tested revision: `4f149960f0d58b19a9cc8dd4dbc7cccb7fbcc318`.
- The following evidence-only commit adds this report and its JSON record;
  the final PR head identifies that documentation commit.
- [Original review follow-up](twostep-relays-review-followup-20260928.md).
- [New commands, results and raw-evidence hashes](twostep-relays-revalidation.json).

**Local revalidation passed. Remote CI on the final head is a separate merge
requirement; this report does not merge or deploy the branch.** The original
124-test / 14-mutation record remains untouched and belongs to the original
implementation. These are newly executed results for the revised tests.

## Corrected oracles exercised

All three focused CTests ran successfully at the independent review revision:
20 native cases (9 transport, 2 selector, 9 wiring/lifecycle), 12.47 seconds.

The total-set switch prebuilds and promotes the exact same committee object.
Actual manager session IDs are checked against production derivation with only
the key-block input changed. The prepared Bus contains the outgoing relay set;
new active/observer Buses contain the incoming set. The distinct observed IDs
in the clean revised run were:

```text
old tentative = 4NDTW4fJUSCPeuyGzVuDH310pNJAtVGGAEhMc/VS4Mk=
new active    = miMoUTCTYFNyE5GIXyNxDyBxy8f0IrP96yrBPig0UaQ=
```

The same-total-set case now uses a current-set next-catchain committee and
observes legitimate tentative reuse, with only the observer requiring a new
Bus. All revised bounded readiness checks completed. The selector sorts input
addresses `62,60,61` into `60,61,62`. The emitted FEC accounting now explicitly
separates target and actual source symbols:

```text
first hops=20 k_target=9  K=9  online=7
first hops=6  k_target=2  K=2  online=7
first hops=62 k_target=30 K=29 online=1
```

The last case checks the actual transmitted 18-byte parts for a 513-byte
payload; it makes no remote-delivery claim with only the source online.

## Mutations

The full previous 14 native mutation classes were rerun against the revised
native sources, followed by restoration and the final clean regression.
Including the two new classes, **16 compiling mutations / 19 executions**
failed at the intended runtime assertions and were restored byte-for-byte.
Every original production-file digest was checked against `7c2c154b`; each
mutated digest differs. Compile errors and harness timeouts do not count.

| New mutation | Build | Test | Intended runtime failure |
|---|---|---|---|
| Manager uses constant `key_seqno=0` in `update_shards` | exit 0 | exit 1 | `TotalSetSwitchRecreatesActiveAndObservers`: `id != tentative[0]` fails |
| Selector omits `std::sort` while retaining offset-zero extraction/deduplication | exit 0 | exit 1 | `OffsetAndTransportIdentity`: sorted `result == {60,61,62}` fails |

The first mutation now exposes actual reuse of the old tentative ID even though
the committee is unchanged. The second establishes that descriptor input order
cannot make sorting coverage pass accidentally. Commands, assertion excerpts,
source digests, exits and restoration results for all 16 classes are in the JSON.
Native mutation testing preceded formatting-only fixture changes; the final
clean build/tests below include those changes.

## Two additional CI failures addressed

The review head had a failing formatting job and two failing unsafe-rotation
source-guard CTests. These failures are kept separate from native test results.

1. Applied the same Clang 21 changed-line formatter used by CI. Its final check
   reports `clang-format did not modify any files`.
2. The unsafe-rotation checker located the future-group boundary by the old
   literal `if (allow_validate_)`. The production eligibility predicate is now
   `groups_eligible`, so this unrelated region marker made the checker refuse
   before testing the unsafe-rotation rule. The checker now anchors the unique
   `for (auto &shard : future_shards)` loop, independently of its outer gate.
   All refusal/counting/derivation/creation ordering, local-hash rejection,
   process-test and CLI-help predicates remain unchanged. The old checker exits
   1 on these same production bytes; the updated checker exits 0 and its seven
   existing mutations still fail for the intended reasons.
3. Explicit fixture byte conversions remove the observed implicit integer
   narrowing warnings. The three focused translation units each pass the real
   configured compile command with `-Werror -fsyntax-only`. This is a strict
   syntax/type check, not a claim that a full repository `-Werror` build ran
   locally.

No production native code, session-ID formula, TL, signature, receive/forward
logic, QUIC or retirement ordering was changed after the independent review.
The follow-up commit touches only test fixtures and the source checker.

## Clean build and regression

Configuration: Clang 21.1.8, Ninja Release, `USE_QUIC=ON`.

| Gate at the clean tested revision | Result |
|---|---|
| Original 45-target affected build | exit 0 |
| Three focused translation units with `-Werror -fsyntax-only` | 3/3 exit 0 |
| Original affected CTest selection, including all 20 revised native cases | 124/124 passed, no failures/skips; 72.35 s |
| Every registered `source-guard` CTest, run separately/serially | 39/39 passed, no failures/skips; 24.46 s |
| Changed-line Clang formatting, changed Python Ruff, whitespace | passed |

The two CTest runs contain **159 distinct tests / 163 executions** (four source
checks also occur in the original selection). They are not presented as 163
unique tests. Existing disabled classical tests and the excluded full-chain
node launcher are unchanged from the original documented regression scope.

Before the build, whole-host usage was sampled at approximately 4.61 cores and
12.59 GiB on a 192-core/125.47-GiB host; the admission added estimates of 8 cores
and 16 GiB for the build. Tests sampled approximately 3.69 cores/12.42 GiB and
added estimates of 16 cores/16 GiB. Both are below the two-thirds resource cap.
No deployed services or blockchain data were changed.

### Reproduce the clean tests

From the repository root in the configured build:

```sh
python3 - <<'PY'
import json, re, subprocess
from pathlib import Path
record = json.loads(Path('test/validator/consensus/twostep-relays-revalidation.json').read_text())
subprocess.run(record['clean_build']['command'], check=True)
names = record['regressions']['names']
assert len(names) == 124
subprocess.run(['ctest', '--test-dir', 'build', '--output-on-failure', '-j4',
                '-R', '^(' + '|'.join(re.escape(name) for name in names) + ')$'], check=True)
subprocess.run(['ctest', '--test-dir', 'build', '--output-on-failure',
                '--no-tests=error', '-L', 'source-guard'], check=True)
PY
git diff --check
```

`$REPO` in recorded native/mutation/strict-check commands represents the checkout
root; expand it to the actual checkout path before direct replay. The three
strict checks use the build directory as their working directory, as in its
compile database. The raw local logs are retained under the ignored
`build/twostep-validation-7c2c154b/` directory and bound by SHA-256 in the record.

The simulated actor-network, empty candidate, controlled masterchain snapshot,
non-reopening retirement and real-socket/deployment boundaries described by the
independent review remain unchanged. Relevant remote CI must validate the final
branch head before merge; success on an older head is not promoted here.
