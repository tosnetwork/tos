# Closed-gate production runtime frontier

This experiment measures the existing production call sequence. It does not
implement the missing admission/replay connection or authorize execution.
No final production source changes, synthetic host identity, admitted input,
proof token, or account replay call are introduced by the test.

## Reproduction

Build `test-tos-collator` and `crypto/create-state` with `-j32`. The existing
account-binding disk fixture registers its test engine; the real collator,
configuration resolver and configured-adapter factory construct the objects.
The debugger wrapper only observes function entry and forwards the real exit
status. It never calls an inferior function or changes an argument/register.

```sh
trace_dir=$(mktemp -d /tmp/workchain-frontier.XXXXXX)
WORKCHAIN_FRONTIER_BINARY="$PWD/build/test-tos-collator" \
WORKCHAIN_FRONTIER_OUTPUT="$trace_dir" \
cmake -DCOLLATOR="$PWD/crypto/test/workchain-runtime-frontier.py" \
  -DCREATE_STATE="$PWD/build/crypto/create-state" -DSOURCE_DIR="$PWD" \
  -DBUILD_DIR="$PWD/build" -DACCOUNT_BINDING_ONLY=ON \
  -P test/test-counter-disk-integration.cmake
python3 crypto/test/workchain-runtime-frontier.py --check "$trace_dir"
```

Both commands must succeed. Missing symbols, debugger failure, missing trace,
unexpected exit, or a mismatched sequence fail rather than skip. This is a
manual integration experiment, not an added CTest/CI registration. Debugger
availability and ptrace permission are prerequisites. Existing normal CTests
remain independent of this diagnostic dependency. The observer is synchronous
at breakpoints and changes timing; its durations are not performance evidence.

## Observed result

| Query | preinit | configuration | adapter | validator set | old-state unpack |
|---|---:|---:|---:|---:|---:|
| Bootstrap (validator-set/old-state positive control) | 1 | 0 | 0 | 1 | 1 |
| Account binding refused | 1 | 1 | 1 | 0 | 0 |
| Configuration callback failure | 1 | 1 | 0 | 0 | 0 |
| Authenticated-state callback failure | 1 | 1 | 0 | 0 | 0 |
| Early no-stats query | 0 | 0 | 0 | 0 | 0 |

The early no-stats fixture rejects excessive shard depth before preinit, not
after a silent traversal of these sites. Its empty trace is explicitly checked,
and the checker requires exactly these five query traces. The existing observer
separately requires `delivery=unconfirmed` for this query. Configuration and
adapter counts have their nonzero witnesses in the binding query, corroborated
by the existing independent callback and ownership observations.

The real account-binding query stops in `check_this_shard_mc_info`, called by
`do_preinit`, after adapter construction and before `check_cur_validator_set`
and `unpack_last_state`. Its existing observer confirms recorded delivery,
configuration ownership 1 -> 2 -> 1, zero transactions and no candidate export.
These are scoped observations, not a claim of zero allocations, zero earlier
authenticated reads, or unchanged state-proof bytes. The debugger's adapter
entry count alone is not construction-success evidence; the existing ownership
and adapter-success observations supply that distinct fact.

There is no runtime admission or replay observation to report. Source inspection
finds no batch admission or account-settlement replay call in the
`ResolvedWorkchainAccountBinding` live alternative. The retained
`ResolvedWorkchainBlockExecution` alternative has its separate singleton
transaction/replay entry points; it is not this path. Absence of symbols in the
release binary is not used as a zero-call
measurement: inlining can remove symbols. The authenticated identity remains a
separate construction dependency: the current two-reference configuration shell
does not supply the required instance domain. This experiment neither tests nor
implements a missing-domain failure. It does not invent a domain to bypass it.

## Attributed controls and restoration

1. Replace only the earliest refusal with success in a temporary collator build.
   Compilation succeeds. The query still exits 2 and the engine still executes
   zero times, but the actual sequence now reaches validator-set validation and
   old-state unpack. The frontier checker fails on their counts 1 != 0. The
   existing disk fixture separately rejects configuration calls 2 != 1. Thus
   the new check does not merely test eventual failure, and its red is not an
   inference from an error string. This is a counterfactual control, not a
  proposed gate relocation. Restore exact source bytes and rebuild before
  any subsequent experiment.
2. Suppress just the old-state counter increment in the debugger script. The
   fixture completes successfully, but the bootstrap trace has the real event
   and a zero count, making the frontier checker fail. Thus the zero count in
   the refused query has a separately exercised nonzero witness. Restore the
  script byte-for-byte and rerun both commands.
3. Add one extra trace file to an otherwise passing observed corpus. The exact
   query-inventory check fails; removing the added file restores success without
   changing any observed trace.
4. In a separate copy of the five-file corpus, give the early no-stats query a
   consistent nonzero preinit count and event. The row assertion rejects it while
   the file inventory and all other rows remain unchanged. This is a checker
   input control, not an observed production execution or a fabricated input to
   the engine. The original observed corpus is never edited.

The counterfactual's later refusal is identified from its retained log and the
unique `cannot execute configured workchain` prefix: `fetch_config_params`
calls `validate_required_workchains`, whose account-binding arm also refuses.
It is not evidence that the earliest gate is the only barrier, nor a separate
mutation localization of that later barrier.

This fixed binary/fixture observation is not a general call-count instrument:
partial inlining in future builds could leave an out-of-line symbol while
hiding other calls. Fully missing symbols fail at breakpoint setup. Missing
trace delivery also fails at the wrapper independently of the debugger exit
code; child-exit forwarding alone is not a debugger-success certificate.

The committed measurement includes exact substitutions, original/mutant/restored
hashes, reconstruction from restored source, binary hashes, raw diagnostics and
final traces. An initial debugger API compatibility failure and a fixture-slot
capacity failure are setup failures, not mutation evidence. Only this run's
failed fixtures were moved to its temporary evidence directories; other retained
fixtures were untouched. No source gate is removed in the final tree.

The initial `runtime-frontier-controls` record is a pre-review checkpoint.
`runtime-frontier-followup-controls` supersedes it with both source controls
rerun using the final five-query checker, plus the two corpus controls. The
corpus-inventory check runs after row checks so it does not mask the gate
control's distinguishing count failure when that fixture exits early.

## Consequence

This closes the requested measurement of the actual early stop, not the runtime
admission/replay seam. Advancing production execution requires deliberate wiring
and authenticated identity construction; repeated private-component tests or
local identity defaults cannot supply those. All activation gates, singleton
semantics, and I13 acceptance status remain unchanged.
