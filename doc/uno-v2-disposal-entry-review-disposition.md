# Coordinator disposal entry: boundary review disposition

Base: `e90afc900`. This unit prepares and serializes actual private Native
transactions, but does not activate their address exceptions or complete M1.
The read-only review is `~/memo/reviews/uno-v2-disposal-entry-review.txt`.
The reviewer ran the new test and all 82 block tests successfully. Finding
numbers below refer to that review, not the earlier three-round audit IDs.

## Disposition

| Finding | Disposition | Evidence or remaining obligation |
| --- | --- | --- |
| 1: every context error currently votes candidate rejection | Disputed present-tense claim; accepted production prerequisite | This factory has no production caller, and does not call the execution-error predicate. A plain Status is not itself a vote. It must not be wired by classifying every untagged error as candidate-invalid. Also, exceeding a valid authenticated count bound is different from resolving an inconsistent configuration: the former can invalidate a candidate, while the latter cannot. Do not label both as authenticated-state corruption. Typed configuration resolution, source-aware admission and the final adapter remain required. Header comments explicitly forbid the unsafe shortcut. |
| 2: existing narrow exception boundary would be insufficient | Deferred, required before production integration | No new catch is installed in this post-admission factory. Fully detached Native closures are required; builder, allocation and acquisition failures must retain their source. Neither a Result signature nor the legacy two-clause dispatch catch establishes containment. The actual complete-host boundary must cover all thrown types, not assume CellCreateError/CellWriteError derive from VmError. |
| 3: missing envelope-context witnesses | Fixed for five independently reachable conditions; unpack claim narrowed | Add custody-only inputs with anycast, a foreign workchain, created LT at the transaction start, future generation time and emitted LT at the start. Neither own-account credit validation nor bounce planning handles those inputs after the loop guard, so each removal control can reach its intended assertion. Envelope/message decoding already occurs in the canonical decoder, and standard destination decoding occurs for every envelope in the own-credit pass; those repeated unpack checks are not claimed as new independently reachable malformed-input cases. |
| 4: retained credit never load-bearing in allocation test | Fixed witness; authorization explicitly not claimed | Add an outgoing transfer of 1150 against 1000 old cash, 100 own import and 10 incoming allocation. It succeeds only with the retained foreign 100, leaving 60. This pins the mechanical ordering, not permission to spend an unexpected bucket. The engine must preserve that liability and authorize any sweep; Native cash conservation alone cannot prevent its misuse. |
| 5: redundant count and unreachable fee overflow checks | Fixed / documented | Remove the extra uint15 count guard: the decoded uint15 inbox and at most one output per item already establish it. The independently configurable output bound remains. Keep checked money accumulation, as required by arithmetic discipline, and document the current less-than-2^135 bound. No independently reachable fee-overflow test is claimed. |
| 6: routing works only for two participants | Disputed | There are two legitimate Native entry roles, not necessarily two state participants. A logical SEND to a registered confidential account is not a Native message to that account. Native messages to other participant addresses still require disposal under section 11.3. An envelope in another workchain is not a final import for this batch; retaining the old own-account selector's skip behavior is not the new full-inbox contract. |
| 7: original-destination source needs a unique disposal producer | Accepted integration invariant | The enclosing host must resolve one coordinator, construct one entry, derive every bounce from the authenticated inbox, allocate LTs and reconstruct OutMsg evidence under the versioned source exception. The factory does not establish those global conditions. No additional wire permission or arbitrary source-selection authority is introduced. |
| Missing direct compute-phase assertion | Fixed | The new fixture now explicitly asserts all five ordinary phase pointers are absent; serialization still independently rejects them. |

## Implemented transaction behavior

The strict entry and importing participant share their existing binding,
identity, declared read/write, ordinal and data validation with the new explicit
disposal entry. With no disposal context they retain their existing semantics.
The new context requires the custody role, price configuration, workchain table,
disposal profile and count limits explicitly. It is not an authentication token.

Own messages are credited once. Custody messages remain that participant's
obligation. Other final destinations are passed to the shared Native disposal
planner. Affordable bounces preserve the prior processing balance and fund both
the returned message and its fees from their own incoming value. Retained
messages increase cash. Only then are declared internal allocations applied.
Error and exception paths never authorize retained credit.

Each bounce gets the next checked LT, contributes its collected Native fee,
and enters both the output vector and its private serialization seal. The
vectors are allocated before sealing. No caller Account or message queue is
mutated, including on preparation failure. The caller must discard a failed
private transaction rather than treating a partial object as committed state.

The main mixed fixture independently decodes new Native account balances,
serialized fees and outgoing messages, combines those with reconstructed InMsg
credits, and checks both account rows against internal transfers. It does not
substitute the planner's row for the actual serialized artifacts.

## Deliberately not claimed

- Bucket-state encoding, bucket authorization, or business Deposit/return
  validation. In particular, unexpected value is not permission to increase
  backing or spend operating funds.
- Native OutMsgDescr or queue publication, complete inbox authentication,
  aggregate admission, or the live semantic address exceptions.
- A multi-account commit/rollback or complete M1 acceptance demonstrated by
  this transaction-level fixture alone.
- New error-origin classification, or coverage of every existing exception
  clause by this fixture.
- Independent fee-overflow reachability under the current price/count bounds.

The review's binary-string observation is supporting evidence, not sufficient
build provenance by itself. The recorded rebuilds, source/binary hashes and
raw test outputs are the provenance for the controls. Manual removal controls
are distinct from recurring mutation CI; these test assertions run through the
existing CTest-registered block test.

## Rebuilt removal evidence

Seventeen independent controls rebuilt successfully and failed the actual
NativeDisposalEntry test: retained credit, collected fees, published outputs,
output sealing, reused message LT, unchecked LT increment, inbound/outbound
counts, distinct roles, price version, custody exclusion, the five isolated
context predicates, and deferral of retained credit until after allocation.
The deferral control preserves the original ordinary funding case and fails
the new load-bearing transfer case; it is not just another early balance
failure. The five context controls reach the custody-only assertions. These
are state/numeric/rejection predicates, not exact error-text assertions.

After exact restoration, all five related CTest targets pass (3.91 seconds),
and standalone transaction-header compilation passes. Raw outputs, exact
substitutions, review snapshot and final source/binary identities are in
`measurements/uno-v2-disposal-entry-evidence.json`. The review source snapshot
precedes the agreed test and defensive-comment corrections. This remains
manual mutation evidence, not recurring mutation CI or complete M1 acceptance.
