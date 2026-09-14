# Session admission core: partial node-integration item 1

Status: this increment advances item 1 but does **not** complete it. It adds a
bounded history-reader contract, native epoch normalization, immutable committee
ownership and fail-closed admission decisions. The native manager still does not
construct the reader, call `NativeCommittee::derive`, or pass the owned context
to a consensus actor.

## Authenticated history contract

`resolve_authenticated_session_birth` starts from an independently selected tip
and asks its reader for one exact observation at a time. It passes the accumulated
chain to the existing birth selector instead of copying birth semantics. A reader
error is returned unchanged. Missing history and budget exhaustion never become a
local-tip birth. The result is constructible only through this resolver, but that
construction restriction is not proof of authenticity: the production adapter
must still authenticate every block and state against one finalized native chain.

The intended native reader must pair `NativeFinalizedHistory` with exact state
loading. For every requested coordinate it must establish the block root, file
hash and resulting state root; extract the current native epoch from that state;
and return the exact authenticated predecessor. It must not use an unfinalized
head, a cache-only answer, or the newest locally available state when an archive
read or budget fails. That concrete reader is still open in this increment.

## Epoch mapping

`map_native_session_epoch` accepts the native session ID produced by the existing
canonical manager encoder. It does not implement a second session-ID grammar.
It binds the full election-cell hash, native options hash, shard, catchain and
vertical coordinate. The key-block coordinate is retained only for the native ID
variant that encodes it; older variants normalize it to zero so one lifetime does
not acquire a coordinate copied from a later key block.

The standalone cases cover split and merge shard coordinates, options changes,
vertical coordinates and both key-block variants. These are controlled mapping
cases, not native manager executions. The manager call site must supply values
from the same authenticated birth state and must use the existing encoder output.

## Immutable admission

`SessionCommitteeContext` owns both the authenticated birth and the derived
committee by value behind an immutable shared pointer. Derivation receives the
selected birth block, never the later state at which a node noticed the session.
A derivation error is returned unchanged and cannot fall back to another registry
or to historical authentication.

Admission separates transition from contradiction:

- a different native session ID requests a new context;
- the same ID with different epoch metadata is contradictory and is refused;
- the same ID and epoch with a different birth is contradictory and is refused;
- the exact same lifetime reuses the existing context without deriving again.

This preserves an already admitted context when a candidate new session fails.
It does not decide when a native session terminates; the manager must make that
lifetime decision from the native session ID and existing rotation behavior.

## Sibling-comparison probe

The requested comparison audit found three observable behaviors in the existing
selector. `EVIDENCE/comparison-siblings.log` is the compiled reproduction.

1. A same-ID metadata disagreement at the first observation returns
   `session-birth-not-current`, because no current candidate exists yet when the
   disagreement is classified. This fails closed, but it conflates "future or
   absent" with contradictory metadata. It is recorded and not changed here.
2. `valid_epoch` accepts a zero native-options hash. The new native mapping rejects
   that value before admission. Whether the selector itself should reject it is a
   separate compatibility decision and is not silently changed here.
3. A contradictory observation link returns `session-birth-link`; that comparison
   already distinguishes chain contradiction from a legitimate epoch transition.

## Executable evidence

The admission executable has 21 named cases. Eighteen source mutants compile,
fail their exact named assertion only after `SETUP_OK`, and restore a passing
21-case baseline. The two mutation predicates are byte-identical to the accepted
selector harness. A 378-execution witness matrix gives every case at least one
compiled named-assertion failure.

The test target and mutation harness are registered with CTest in the existing
session-birth project. The focused workflow already configures, builds and runs
that project, so no new workflow shell state is introduced. A deliberate removal
of the options guard compiled successfully and made the workflow CTest command
fail at `zero_options_are_refused`; the mutation CTest also refused its broken
baseline.

## Still required to finish item 1

The concrete finalized-history reader, manager insertion, frozen insertion
inventory, freeze evidence update, complete production build, native call-site
mutations and consensus-actor ownership remain open. Observer admission and
restart behavior also remain open. Until those exist, no validator session
consumes `NativeCommittee` in production and item 1 is incomplete.

No consensus certificate path, contract, chain-apply path, language-parity path,
public serving path or network configuration is changed. No activation threshold
or pending approval is satisfied by these standalone checks.
