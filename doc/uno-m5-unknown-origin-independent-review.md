# Independent unknown-origin counter review

Target: A `76a0151ea9be425c052a924a7f5125a4b118619c`.
This is a retrospective review, not an independent pre-observation prediction.
No A files or B production source were modified. A detached temporary checkout
provided the pinned driver, injection and collator source. Relevant translation
units were rebuilt/relinked using existing generated headers and dependency
libraries; this is not a clean full build or complete M5 acceptance.

## Four findings

1. The counter genuinely increments at the collator boundary. Removing ONLY
   the increment while retaining the actual post-execution injection, logging
   and -7201 conversion makes the actual live driver fail at its counter oracle.
2. The injected result is genuinely unclassified on arrival at that boundary:
   code 0 and its injected cause are logged there, after successful real engine
   execution. It was not already classified as a known local error upstream.
3. Result and publication observations are separate: the negative has the exact
   -7201 result/message, independently read statistics show zero transactions,
   and no candidate file exists in the fresh output directory. These are not
   inferred from the return code.
4. Validator direct unknown injection is NOT established. Shared normalization
   code is shared implementation, not shared end-to-end execution evidence.

## Exact isolated reversion, retaining the real injection

The pinned `test/m5-live-unknown-control.h:33-35` forwards to the real registered
engine and uses TRY_RESULT; only after that execution succeeds does it discard
private effects and return `Status::Error("injected unclassified failure after
real Failed execution")`. Configuration and proof-work hooks are forwarded.
No classifier is called by the injection itself; the no-code constructor is
legacy code 0, independently observed in the real boundary log below.

B rebuilt the pinned `test/test-m3-live.cpp` and `validator/impl/collator.cpp` in
`/tmp/b-unknown-source`. For the mutant collator build, only lines 24-27 of
`workchain-unknown-origin.h` (load/CAS increment loop) were removed. Early known
code handling, the diagnostic and the returned local error were retained. The
same compiled driver/injection was linked into both binaries. Other shared
library observers remain unchanged; this probes this collator's returned-unknown
path, not removal of every observer across the program.

Each run used a fresh copy of A's existing rejected-unknown predecessor DB,
with an independently decoded prepare block ID (wc2 sequence 5) and its BOC
file hash. The original source DB was not modified. A first attempt used the
wrong earlier DB snapshot and stopped with `651: not in db`, before execution;
that was a fixture acquisition failure, NOT a business/control red. The correct
DB contains the recorded prepare predecessor. Missing generated-header include
paths were likewise build setup failures, corrected before measured runs.

| Build/run | Real driver exit | Count sidecar | Named outcome |
|---|---:|---:|---|
| Original pinned observer | 0 | 1 | unknown injected, expected refusal observed |
| Increment removed only | -6 (SIGABRT; shell 134) | 0 | `test-m3-live.cpp:356`, `unknowns == (enabled && unknown_control ? "1\\n" : "0\\n")` |
| Original observer restored, fresh DB | 0 | 1 | original control passes again |

All THREE runs still log the same reached boundary and original status:
`WORKCHAIN_UNKNOWN_ORIGIN boundary=collator-account-batch code=0 cause=injected unclassified failure after real Failed execution`.
They still produce the same -7201 result and no candidate. Thus neither the
log nor the error conversion can stand in for counting: precisely the count
oracle distinguishes the mutant. The positive driver exit means the deliberate
negative control passed; count=1 is NOT a successful wiring acceptance run.

## Why this is the unclassified branch

`crypto/block/workchain-unknown-origin.h:21-23` returns immediately for success,
CandidateInvalid (-7200), or the known local classes -7201/-7202. Code 0 is none
of them (`workchain-execution-errors.h:16-19`). Lines 24-32 then count, log original
code/cause, and convert to `unclassified workchain execution failure`, -7201.
The log includes the ORIGINAL code, so a known -7201 from an earlier check could
not produce this observation.

`workchain-account-engine.h:354-356` returns the engine result after checking
proof-meter status; the real run reports work=7 and execute=1. The post-execution
code 0 propagates through execute-and-settle's error return and the TRY_RESULT
at `collator.cpp:3557-3559`, before installing the successful settlement artifacts.
`collator.cpp:2533-2535` invokes the observer with `collator-account-batch` and
returns its error. This contrasts with proof-preflight: a failure there would
log `account-proof-preflight`, and could not have this successful execution/work
observation followed by the injected post-execution cause.

“Genuinely unknown” means an unclassified returned status on this execution
path, created deliberately by the test. It is not a demonstration of a natural
DB/OOM fault or a complete provenance taxonomy. Already-known but wrongly assigned
categories bypass counting; zero cannot certify their correctness.

## Return code and publication surface, observed separately

B's separate artifact reader (`run.py`) checks these fresh outputs AFTER the
real driver completes or aborts, including the mutant whose driver stops at the
count assertion before its later publication assertions:

- `unknown-enabled.result`: `collate -7201`;
- `.message`: `unclassified workchain execution failure`;
- `.calls`: config=5, execute=1; `.calls.units.1`: 7;
- `.stats`: delivery=recorded, visited=1, adapter=1, owners_before=1,
  owners_during=2, owners_after=1, transactions=0;
- `unknown-enabled.candidate`: absent in each newly created directory;
- closed-side unknown count: 0, separately from the deliberate ON injection.

This independently checks the publication observations even when A's driver
aborts before reaching them. It does not derive zero transactions from -7201.
Source inspection corroborates the order: the engine error exits before the
successful settlement's Native artifact adoption, transaction statistic increment,
account-root installation and export loop in `create_workchain_account_batch`.

Observation limit: statistics and candidate-file publication at the collator
boundary, not a fresh exhaustive account/queue/DB-root equivalence proof. No
additional mutant that writes a DB root while lying about statistics was run.
The real engine computed private effects, but no successful settled transaction
set escaped this injected error. The process's deliberate proof work is nonzero;
“zero transactions” must not be rewritten as “zero execution.”

## Validator: exact remaining gap

`validate-query.cpp:6687-6696` runs proof admission, execution/settlement and
artifact comparison on an independently reconstructed candidate. Its catches
at 6701-6717 may already assign known local/candidate codes based on that scope.
At 6718-6721, CandidateInvalid takes reject_query; other returned errors pass
through the shared observer labeled `validator-account-replay` into fatal_error.

The observer body and process-local atomic are shared, so tests of its mapping
and increment semantics apply to that function. They do NOT demonstrate that a
raw code 0 reaches this validator call site, that it is counted exactly once in
replay, that earlier normalization/catches do not intercept it, or that the
validator's final abstention/publication surfaces are correct. This control's
collation fails before exporting a candidate, so it never enters validator replay.
Calling the shared function with the string `validator-account-replay` would not
close the gap either. Normal replay reporting zero is not fault-injection evidence.

The missing test is a valid accepted candidate and its authentic predecessor
fed directly to validator replay, with raw code 0 injected after successful real
engine execution before effects escape; require the exact validator boundary
log, count delta one, final LocalUnavailable/abstention and no accepted-state
publication. Remove only the relevant counter increment and require its named
counter assertion to fail. It remains **not measured**, not structurally implied.
Proof-preflight's own actual unknown injection was not added in this review.

## Process-local scope and remaining limitations

`workchain-unknown-origin.h:10` defines an inline process-local atomic initialized
to zero; accessor 15-16 only loads it. The increment saturates at uint64 maximum
rather than wrapping. There is no consensus serialization, authenticated counter,
DB restore or runtime reset in this implementation. The sidecar in
`m5-live-unknown-control.h:7-9` is a test observation written at exit, not restored
into the counter or consumed as consensus state. New process/restart zero is
expected, not a defect. Saturation is inspected here, not stress-tested to its
maximum. Log filters do not guard the increment in the source.

Only returned, unclassified statuses reaching these observers are counted;
swallowed errors, exceptions already mapped to known codes, wrong known-category
assignments and unexecuted paths are not certified by zero. No persistence change
is proposed. No guard is retired, no missing validator control marked green,
and no full-suite or complete classification acceptance is claimed.
