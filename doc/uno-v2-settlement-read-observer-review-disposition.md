# Private settlement read observer: review disposition

Base: `4cffaede1`. This is D31 integration work, not live M1 acceptance.
The first review is recorded in memo at
`reviews/uno-v2-settlement-read-observer-review-20260908.txt`.

| Finding | Disposition |
| --- | --- |
| M1: existing-tree reuse has no positive | Added successful settlement over an existing proof root, comparing rebuilt accounts and AccountBlocks with the private-source result. The corresponding follow-up mutation compiled and exited 1. |
| M2: refusal reason not distinguished | Retained the behavioural refusal/injection/call-count assertions and added the exact footprint diagnostic. The message assertion supplements, not replaces, behaviour. |
| M3: second weak-pointer lock | Moved the read-through operation into NodePtr. One lock now spans pre-load observation and first-load proof marking. There is no second observer-only lock on each read. |
| M4: private tree lifetime | Recorded the dependency next to ownership. Private tree ownership must not escape this frame; retained-meter evidence contains hashes, not tree owners or LoadedCells. Added a fresh proof over returned state, descending into an untouched account. Retaining a private tree compiled and exited 1 at Native's anti-nesting CHECK in the fresh proof traversal. Caller-owned trees retain their existing Native lifetime obligations. |
| M5: root-only anti-nesting assumption | Added a pre-acquisition observer that refuses encountered live nested UsageCells before the source load reaches Native's CHECK. Added a bare root with tracked descendants; it returns LocalUnavailable before engine invocation. It does not scan the entire old dictionary merely to validate tree ownership. The corresponding follow-up mutation compiled and exited 1. The post-execution nesting clause is defensive and has no isolated runtime witness in this cut; it is not claimed as separately accepted coverage. |
| L1: content vs path union | Clarified the content-hash union. It does not bound usage-tree path growth or repeated semantic work. Native proof emission memoizes by hash AND Merkle depth: hash-only output deduplication is limited to the depth-zero case, not arbitrary account special cells. Full-block proof and work acceptance remain open. |
| L2: immutable-root tautology | Removed the misleading immutable-root equality assertion from the refusal witness. A refused Result returns no private settlement artifacts; this is not proof of an atomic live database commit. |
| L3: mutable tree capability | Removed public lock_tree(). Observer construction takes a NodePtr and privately pins the tree; it does not give a borrower setters for proof marking or the existing callback. |
| L4/L5: stale plan/formatting | Reflowed the settlement lambda and corrected the stale overlay-admission comment. Focused re-review closed M1-M5 and requested the final-source direct controls recorded below. |

The added refused-read proof fixture initially used a leaf. That was invalid
test setup: Native create_pruned_branch preserves loaded leaves. The corrected
fixture has a non-leaf child. Before and after the refused read, proof BoC bytes
must match, and the virtual proof must still refuse access to that child. The
initial fixture failure is not counted as a control against production logic.

Other source/Native exceptions still need the enclosing provenance-aware
boundary. Swallowing the specific observer exception is covered by a sticky
flag; a future callee translating it to another exception must preserve local
provenance at that outer boundary. No new wire field, budget value or live
execution permission is introduced here.

Follow-up controls are archived in
`measurements/uno-v2-settlement-read-observer-followup-controls.json`.
All four mutated builds succeeded and all four test runs exited 1. Moving the
observer after Native proof marking changes the refused-read proof bytes; the
restored non-leaf fixture passes. These are manual recorded executions, not a
recurring mutation CI gate. The earlier artifact covers the earlier source cut.

The pre-review restored build, seven regression tests and source/binary hashes are in
`measurements/uno-v2-settlement-read-observer-followup-final.json`. The node and
disk-collator targets also built successfully. These checks do not close the
live multiaccount proof, provenance, resource or atomic-publication obligations.

After focused-review disposition and direct-control reruns, all seven regression
tests passed again (36.75 seconds); all seven named build targets succeeded.
Final-source hashes and full final build/test output are recorded in
`measurements/uno-v2-settlement-read-observer-acceptance.json`. Earlier artifacts
retain their own source cuts and are not presented as this final source.

## Focused follow-up review

Recorded in memo as
`reviews/uno-v2-settlement-read-observer-followup-review-20260908.txt`.
The reviewer read the artifacts but did not independently execute tests.

| Finding | Disposition |
| --- | --- |
| F1: final-source direct union/hook controls missing | Closed. Both final-source mutated builds succeeded and both tests exited 1: removing only the union predicate incorrectly accepts the injected read; removing the NodePtr hook yields zero observations instead of three. Restored build passed. See `measurements/uno-v2-settlement-read-observer-final-direct-controls.json`. |
| F2: observer construction exception | Documented the synchronous caller/private-owner lifetime contract next to both sites, and why stale wrappers may be wrapped safely. The general constructor can throw invalid_argument for contract misuse; it is not a candidate-data parser. Enclosing live source/lifetime containment remains required. |
| F3: post-execution nesting witness missing | Accepted as a coverage limitation; removed the claim of independently established post-execution nesting coverage above. The pre-acquisition fixture and union-refusal fixture exercise different predicates. |
| F4/F6: observer exceptions and attempted reads | Added the generic interface contract: installing frames contain observer exception types, and notification counts attempts, not successful reads. The two private scopes are sequential with separate installing handlers. Cell load/provider exceptions could already propagate before this cut; only the new observer exception contract is added here. |
| F5: assumed out-of-line overhead | No performance claim or change. before_load and NodePtr::load_cell are defined in the same translation unit, so an optimizing compiler can inline the former. A source-level out-of-line definition alone does not prove the reported call overhead. Measure generated code/latency before asserting that cost. |

The review's proposed global `visited_cells subset of charged_hashes` statement
needs an additional precondition and is not adopted as written: an existing
caller-owned tree may already have marked content outside this attempt's union
(the refusal fixture deliberately preloads an unrelated account). The observer
constrains attempted reads during its scopes, not historical marks or emitted
proof closure. Merkle-depth-sensitive output accounting remains separate.

The observer is tree-wide. Live integration must preserve the synchronous
non-reentrant ownership interval or scope the mechanism more narrowly; the
existing-tree success fixture is over ShardAccounts, not an entire shard-state
tree with callbacks reading unrelated branches. No live proof claim follows.
