# Multi-account registry binding review disposition

Scope: explicit local registration and descriptor-bound configuration lookup.
This is not resource admission, live scoped dispatch, or M1 completion. The
production default registry registers no multi-account engine. Existing generic
dispatch still rejects this path rather than treating it as a singleton.

Verbatim review: `~/memo/reviews/uno-v2-account-registry-review.txt`.
The reviewer read source; it did not build or run tests. Runtime evidence is
separate and must not be attributed to the review.

## Dispositions

- Whole-block scope: disputed. `WorkchainExecutionScope` distinguishes
  AccountCompute from BlockTransition, not singleton from multi-account
  transaction permissions. V2 explicitly retains BlockTransition. Returning
  absence would conceal a registered engine's actual execution granularity;
  adding a third protocol scope is not needed here. A comment now distinguishes
  scope from record acceptance. The unchanged transaction-scope checker still
  rejects participant records on the singleton path; this unit does not loosen
  it. Later live dispatch needs an explicit resolved multi-account alternative.
- Callback exceptions: the offered type-only reclassification is disputed.
  An exception does not establish source provenance. The explicit binding API
  documents propagation to a source-aware enclosing boundary, rather than
  asserting a no-throw contract or converting all VM errors into candidate
  rejection. Throwing callback tests pin VM and virtualization propagation.
  Missing local engines and authenticated configuration acquisition faults must
  not be mapped to candidate rejection by a future caller. Other exception
  categories are not newly claimed as tested here.
- Redundant guards: removed the duplicated activation and active checks from
  the binding method; shared ingress loading and descriptor binding already
  perform them before the callback. Removed the extra account-engine condition
  in the legacy account-compute resolver: registration isolation, declared
  ingress and its engine-map lookup already reject that path. No error-message
  assertion is presented as independent semantic coverage of overlapping gates.
- Default pointer: fixed with a null initializer.
- Witnesses: added compute/multi-account registration conflicts in both safe
  registration directions, reverse resolver isolation, mismatched policy key,
  absent workchain entry, and explicit callback counts for null/rejected payloads.
  The legacy CHECK-based startup registration is not claimed as a new death-test
  result. Public positive tests verify retained roles and exact payload identity,
  and every exercised binding path observes zero account executions.

No amount or metering arithmetic is added. No production resource default,
configuration schema, new error category, or activation permission is introduced.
Successful binding is not a proof that supplied policy values are authenticated,
nor that all host limits have been resolved. Those remain live-integration work.

Six independently rebuilt removal/substitution controls failed at state/result
assertions, not error-string comparisons. Restoration rebuilt the production
validator and both test binaries; the block, configuration and two disk CTests
all passed (5.67 seconds). Exact diff, substitutions, output and artifact hashes:
`measurements/uno-v2-account-registry-evidence.json`. These manual runs do not
constitute recurring mutation CI. The initial stub witness is an explicitly
labeled diagnostic excerpt, not a claim that its full backtrace was retained.
