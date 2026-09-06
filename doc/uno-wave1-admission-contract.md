# Typed candidate admission: isolated first-wave boundary

`workchain-input-admission.h` defines `InputAdmissionResult` as a variant of
`AdmittedInput`, `CandidateInvalid`, and `LocalUnavailable`. `ConfigInvalid`
belongs to a separate policy construction result. None of this API is installed
at a consensus entry point; no param 84 parser or schema is added.

`AdmittedInput` has a private constructor. A single-candidate session visits
every reachable Cell, rejects forbidden special/virtualized candidate payloads,
and builds a detached ordinary DAG bottom-up. Each copied Cell must have the
original hash. It neither trusts `is_loaded()` nor retains lazy references to
source children. The returned root owns its complete materialized closure.
This is not an authentication proof: acquisition of an authenticated witness
and policy identity remains a caller responsibility.

Cell/bit/root increments use a checked remaining-budget operation. The Cell
limit precedes load; bits follow load. Source and detached-node maps are bounded
by the admitted Cell count. The iterative stack contains at most one finish
marker plus four child entries per admitted Cell. Temporary source and copied
Cells coexist, so physical RSS must be measured rather than equated with the
logical input byte limit. No C++ recursion is used.

The first result is retained verbatim. A local load failure does not become
CandidateInvalid on another `evaluate()` call; recovery requires a new session.
Missing candidate/over-budget/forbidden special structure is CandidateInvalid;
load, identity, allocation and construction faults are LocalUnavailable.
Exceptions do not authorize a business-level Failed receipt.

`ResolvedInputPolicy::from_resolved_fields` distinguishes malformed zero limits
(`ConfigInvalid`) from a version this binary cannot execute (`LocalUnavailable`)
and carries the full policy identity. It does not
claim that caller-supplied fields are authenticated or replace D-1's future
pure ConfigParam 84 decoder. Only one candidate root is handled here; the
canonical inbox scaffold, logical-root identity/retry rules across adapters,
Native special-body semantics and proof-cost admission remain open. Do not use
this candidate-only ordinary-Cell policy on authenticated Native queues.

Four tests cover ownership of every descendant under post-admission source
failure, original typed failure retention, protocol rejection before further
loads, and independent config errors. Each was observed red after its specific
property was removed: return the source DAG, repeat failed acquisition, map
special input to local failure, and accept zero policy limits. The assertions
check successful descendant loads, invocation counts and variant alternatives,
not error wording. Private construction is additionally compile-time checked.

Logs: `build/wave1-admission-{detach,sticky,special,config}-mutation.log`.
These tests are not collator/validator admission evidence. Full preflight
remains activation-blocking until the unimplemented adapters and measured
limits are delivered and frozen.
