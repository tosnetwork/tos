# Configuration requirements and milestone boundaries

Read-only follow-up to the non-I13 inventory. Source baseline:
`e317552e7add3727227b481023e29cb1b7188d2f`; governing memo:
`bb3d031ead8ebe50cac6e68be9dafb5b4976b500`,
`TOS_UNO_PRIVACY_WORKCHAIN_V2.md`. Line references below refer to those revisions.
The companion `doc/measurements/uno-m1-configuration-scope.json` pins source
blobs and memo anchors. No tests, builds, production edits or deployments ran.

The earlier phrase “business profile and complete migration sequence not found”
is a discovery result, not a justified assignment of all that work to M1.
The memo separates host configuration, later business operations, capacity
calibration and real-value activation. Some finer delivery deadlines are not
specified; this report does not assign them by inference.

| Question | Verified requirement and source status | Milestone reading |
|---|---|---|
| D36 cadence binding | Memo section 14, line 743 and D36, line 999 require certified cadence in engine_configuration and rejection of a configuration whose cadence differs. Param30 decoding exists; the inspected installation/resolution functions do not implement this cross-check. | No M1 exemption is stated. This is an outstanding installation requirement before using the corresponding V2 profile, not merely M6 benchmarking. The memo does not explicitly name the milestone for delivering the guard. |
| Business profile | Memo sections 12/12.1/14 require authenticated operational/economic parameters distinct from generic resource framing. Generic host parsing and a business-validation callback exist; a concrete complete V2 resolver was not identified. | Split by operation. Host profile identity/resource/version rules are M1. Parameters needed by the operation being tested must be resolved before that operation runs. Do not charge every M3–M5 business parameter to M1. |
| Readiness, migration and rehearsal | Section 14, line 741 and section 18, line 890 require readiness before version/profile enablement, both configuration checks, first-use cut and dry-run counterexamples. Section 17 separately places real-value launch/incident rehearsal in M8. | These are not one M1 deliverable. M1 keeps host gates and applicable version-transition checks; actual deployment readiness is due before the relevant enablement, not only M8. M8 launch rehearsal and M6 capacity/lifecycle evidence must remain separately scheduled. Complete dry-run tooling's M1 deadline is not explicit. |

## D36: a required comparison, not another cadence decoder

Memo section 2.2, lines 79–81 says wc=2 uses shard Simplex timing from authenticated
Param30; there is no independent UNO slot. Section 14, line 743 and D36, line 999
add three requirements: cadence changes are capability events; K and base_compute
must be reaccepted with them; engine_configuration records the cadence underlying
acceptance and configuration installation rejects a mismatch. Section 12.1,
lines 700 and 718 also identifies time-sensitive retirement and payout parameters.

`crypto/block/mc-config.cpp:388` reads Param30, selects the shard rather than
masterchain configuration for a shard workchain, and decodes Simplex timing
(`crypto/block/mc-config.cpp:418` includes target_rate_ms). This is concrete
reusable decoding, not the D36 comparison.

The complete body of `crypto/block/workchain-execution-dispatch.cpp:160` checks
Param84 framing, version/capability, admission version and nonzero bounds. It
explicitly leaves business parameters opaque. The complete transition body at
`crypto/block/block.cpp:1936` enforces ingress destination/descriptor transition
restrictions. Neither reads a certified V2 cadence or compares it with Param30.
The account binding path at
`crypto/block/workchain-execution-dispatch.cpp:416` derives authenticated resource
identity, then delegates business validation to a registered engine at line 451.
The generic frame `crypto/block/workchain-resource-policy.h:129` contains resources
and an opaque Cell, not a typed certified-cadence field.

Thus the D36 guard is absent from these inspected generic functions; a hidden
implementation somewhere else is not ruled out merely by searches. Searches of
non-archived, non-vendored UNO sources and the workchain host sources identified
no concrete V2 business resolver/cadence binding. No implementation or measured
D36 mismatch test is established by this review.

“Not required by design” would contradict the explicit installation rule. “All
D36 remeasurement must finish in M1” would also overstate the memo: section 12,
line 684 and section 17, line 867 put minimum-hardware/full capacity acceptance
in M6. The installation guard and the evidence whose cadence it binds are
separate obligations. The exact guard delivery milestone remains an unresolved
schedule boundary, not permission to install a mismatching profile.

## What business validation means

There are three different objects; calling all three a profile hides the gap.

1. **Host resource/admission contract.** The frame in
   `crypto/block/block.tlb:7` through line 17 describes input, state and work/output
   limits plus opaque parameters. `crypto/block/workchain-resource-policy.h:32`
   recognizes exactly admission versions 2/3/4, and line 66 checks fee permission
   for 3/4. D42 and D46 (memo lines 1006 and 1010) distinguish fee-constructor
   permission from deterministic proof-work metering. These mechanisms exist;
   they must not be reported as missing V2 business parsing.
2. **Authenticated business rules.** Memo section 12, lines 675–678 and section
   12.1, lines 690–709 specify K/amount/fee/lifecycle parameters in Param84
   engine_configuration. Examples include K_collect, pending capacities,
   V_min, pending_slot_fee, registration deposit, fee bounds and withdrawal caps.
   Section 14, line 758 adds the governance pause policy; D36 adds certified
   cadence. Section 14, line 739 requires distinction from the old profile.
   The pure authenticated callback contract exists at
   `crypto/block/workchain-execution-dispatch.h:266`; line 278 receives the whole
   Config and engine configuration. Invocation exists, but an opaque payload
   and a callback contract do not establish a concrete implementation of these
   rules. The generic host cannot certify an arbitrary engine's payload.
3. **Dynamic authenticated state and transitions.** base_compute is also stored
   in `crypto/block/block.tlb:2` and encoded/decoded through
   `crypto/block/workchain-coordinator-state.h:14` and line 32. This is real code,
   not a missing field. That decoder explicitly excludes fee-parameter/counter
   transition validation at line 28. Memo section 12's D28/D32 operation rules
   require more than representing a value: derive fees from authenticated rules
   and verified operations, and check the actual transition. A state codec is
   not an economic configuration checker.

M1's existing fee/accounting host path cannot rely on an unvalidated local fee
schedule. The actual business operation and its complete configuration, however,
follow their milestones: registered SEND/COLLECT lifecycle is M3; deposits M4;
Withdrawal M5 (memo section 17, lines 864–866). Most decisively, section 12.1,
lines 720–723 explicitly says max_bounce_cost and payout_settlement_blocks only
gate M5, M1–M4 do not depend on them, and no local defaults are permitted.
“Full business profile incomplete” therefore cannot mean that M1 must finish
those two parameters or enable Withdrawal. Conversely, a test-only profile does
not prove the eventual business profile valid.

## Readiness, migration and rehearsal are different deliverables

Memo section 14, line 741 requires auditable current/next-validator readiness,
consistent 8/84/descriptor/engine/manifest/zerostate/obligations, then authenticated
migration before ingress opens. Each transition must pass valid_config_data and
valid_config_transition; tosctl dry-run must simulate the sequence.
Section 18 is explicitly an activation-gates table (line 875). Its atomic-config
row at line 890 requires premature v16 and premature admission-profile activation
counterexamples; the condition applies to each such rollout, not just real-value
launch. D42 explicitly repeats this order for the fee-enabled profile.

Generic host checks are already live:
`validator/impl/collator.cpp:5383`, `validator/impl/collator.cpp:5414`,
`validator/impl/validate-query.cpp:7084`, `validator/impl/validate-query.cpp:7115`.
They do not themselves certify deployment readiness. The inspected tosctl
configuration action enum at
`tosctl/src/node-control/commands/src/commands/nodectl/config_cmd.rs:45` manages
local application configuration. The identified dry-run at
`tosctl/src/node-control/commands/src/commands/nodectl/vote_cmd.rs:1040` concerns a
validator bid. No complete V2 configuration-sequence simulator/readiness artifact
was identified by these searches and command-source inspections. This bounded
negative result is unchanged; its milestone attribution is now narrower.

Section 17 explicitly assigns minimum-hardware/capacity and lifecycle handover
to M6 (line 867), and binary/manifest/configuration locking plus launch/incident
rehearsal to M8 (line 869). Those full operational deliverables should not be
counted wholesale as missing M1 host mechanisms. Nor should all configuration
migration be assigned to M6 just because it also concerns lifecycle handover.
The repo implementation plan's stage summary at
`doc/uno-v2-implementation-plan.md:31` is supporting context, not authority to
replace the memo's more specific conditions.

The memo's single word “configuration” in M1 does not specify whether the complete
tosctl sequence simulator must be delivered in M1, or later before the first
applicable rollout. There is no explicit waiver and no precise M1 deadline for
that tool. Report it as a section 14/18 pre-enablement obligation with milestone
delivery unassigned, rather than as a proven M1 blocker or a proven M8-only task.
The isolated test activation authorization does not demonstrate deployment
readiness, and does not change deployment/final commit gates.

## Suggested correction to the progress wording

Keep M1's concrete authenticated host configuration/version/binding checks and
identify D36 installation enforcement as an outstanding cross-configuration
requirement whose implementation delivery boundary needs assignment. Separate
business providers by enabled operation and M3–M5 scope. Move full real-value
launch/incident rehearsal evidence out of the M1 mechanism deficit and retain
it under M8; retain capacity and lifecycle-handover evidence under M6. Track
section 14/18 readiness and full-sequence dry-run separately as pre-enablement
requirements; the memo does not justify silently declaring either completed or
exclusively due in M1/M8.

This is a source and scope finding for coordinator disposition. It does not
choose a new profile schema, cadence mapping, default value, implementation
owner or activation date, and does not change the memo.
