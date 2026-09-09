# I13b mechanism controls (not live acceptance)

Nine controls exercise a private actor and a bounded attempt ledger. No live
engine entry is connected. Bounds here are synthetic; authenticated provenance,
one-time construction of the optional production actor member, and enforcement
at the live stateful entry remain pending. A recorded failed execution is not
refunded. Duplicate, bound exhaustion, and actual allocation failure are distinct.

The scope is a real private actor instance. The probe counts its actual stateful
method body, and the coroutine must explicitly reach its completion marker.
The ledger fixes its bound at construction and cannot be copied or moved;
attempts accept no replacement bound. Zero-bound and two-bound fixtures are
separate instances, not successive limits on one ledger.

Each audit records the exact replacement, predicted and observed mutant hashes,
all three unchanged repository source hashes, and original/mutant/restored binary
hashes. `commands.json` records configure/build/test commands. Mutations modify
only a separate measurement copy. Every restoration explicitly rebuilds
`test-workchain-execution-ledger`, the actual executable reached through CTest
and the Python driver; `all-tests` is not substituted. Compiled mutants must
produce one CTest `fail` with a failure element and the named assertion, never
a skip or not-run. Restored tests must produce one `run` without a failure.

Run `python3 doc/measurements/uno-i13b-ledger-controls/reproduce.py [commit]`
to independently reconstruct the mutants and check the archived JUnit results.
This verifies archived correspondence, not a new execution of the controls.
The commit argument requires a commit containing this unit's new source files.

Earlier eight-control evidence predates the coroutine-completion assertion.
The subsequent in-place rerun was interrupted during its first mutation and
left a mutant in the worktree. That header was restored to its original hash
before the reviewed changes; neither checkpoint counts here. Measurement-copy
overrides remove that repository contamination path. An initial copy build
also failed because its include search omitted the normal dependency directory;
that setup failure is not control evidence. The final copy build explicitly
searches the measurement directory first, followed by normal dependencies.

The bound is not a wall-clock estimate. Storage is at most U tree entries and
lookup O(log U), with U at most the immutable constructor limit. Standard
allocator failure remains a local mechanism outcome, not a substitute for
candidate-bound exhaustion. No consensus error code is added in this unit.

The final driver checks Ninja's compiled source and actual header dependency
against its own source tree before running the binary. A repository driver
rejects a measurement-copy source, and independently rejects a copied header
with the repository source; the latter is a real CTest Failed result. Explicit
copy drivers validate their own copy tree. The normal workflow supplies no
overrides and its registration gate requires the repository driver.

Ordinary regression: 130 actual entries, 121 passed, 9 owner-deferred obsolete
bootstrap shapes, zero unresolved or skipped. `final/comparison.json` checks
each new fixture's raw cause and configuration bytes, not just failed names.
The ordinary regression excludes all four opt-in private harnesses. The ledger
ran separately; the original three harnesses were only enumerated, not run.
The four-name CI observer separately ran four trivial fixtures, including one
real failed driver while all names remained present, under normal and optimized
Python. That checks the observer, not the three private acceptance harnesses.

During the ordinary run the ledger header received comment-only clarification
of allocation exceptions and the future bound classification. After the final
default `-j32` rebuild, all 645 ELF executables in the build tree were byte-equal
to those used by that run (`final/*executables*.json`). The ledger driver and
module were checked separately after their final changes. This is explicit
binary correspondence, not a claim that no source file changed during the run.

Pre-regression cleanup had previously archived 194 top-level diagnostic files
and removed 9 fixture directories. The fresh coordinated preflight found 0,
so performed no deletion. The archive is diagnostic-only, not a database backup.
The extra removed-domain scan retains the same five baseline generated-tag
path findings; it is not reported green or waived by this unit.

Final review scope limits: the driver's path check is not a whole dependency
closure or freshness attestation. An override directory could shadow a different
dependency, and CTest alone does not rebuild a stale binary. This unit explicitly
rebuilds before each run and restores each measured executable; the workflow also
builds before CTest with no overrides. Before downstream reliance on the driver
as a standalone provenance gate, require all dependency paths and build freshness
or committed-byte correspondence. Per-control maps pin the three mutated inputs;
the two CMake modules are pinned in the final manifest, not per-control maps.
The opt-in module requires Ninja (the workflow explicitly selects it).

The optional production slots still permit reset/re-emplacement; live integration
must enforce one-time construction within each actor. A duplicate attempt is a
host-contract fault, to be treated as local failure by that future boundary, not
as evidence of candidate invalidity. Bound exhaustion is separately candidate
invalidity. This unit defines distinct outcomes, not live consensus error mapping.
The 645-executable manifests use paths relative to the build root, including
subdirectories, not basenames; equal names in different directories do not collide.
